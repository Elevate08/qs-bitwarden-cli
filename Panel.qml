import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Quickshell
import qs.Commons
import qs.Ui
import "BitwardenModel.js" as Model

Panel {
  id: root
  moduleName: "io.github.elevate08.qs-bitwarden-cli"
  ipcTarget: "io.github.elevate08.qs-bitwarden-cli"
  manageIpc: false
  // =========================================================================
  // View
  // =========================================================================
  //
  // Everything here draws; the vault (state, commands, timers, IPC) is
  // Service.qml. tests/service-host.test.js enforces that neither side names
  // the other's controls.

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  // -------------------------------------------------------------------------
  // View contract
  // -------------------------------------------------------------------------
  //
  // What the vault may ask of a view, via `presenter` or eachView(); it names
  // no control by id (enforced by tests/service-host.test.js).

  // The monitor this copy of the bar is on, for choosing a presenter.
  readonly property string screenName: root.QsWindow && root.QsWindow.window && root.QsWindow.window.screen
    ? String(root.QsWindow.window.screen.name || "") : ""

  function showPopout() { root.controller.show() }
  function hidePopout() { root.controller.hide() }

  // The controls the logic moves the cursor to, by name.
  function fieldFor(name) {
    switch (name) {
      case "search": return searchField
      case "pass": return unlockForm.passwordField
      case "pin": return unlockForm.pinField
      case "email": return emailField
      case "loginPass": return loginPassField
      case "code2fa": return code2faField
      case "deviceCode": return deviceCodeField
      case "sendName": return sendNameField
      case "formName": return formNameField
      case "formPass": return formPassField
      case "pinSetupPin": return pinSetupPinField
      case "fpMaster": return fpMasterField
      case "keyCatcher": return keyCatcher
    }
    return null
  }

  function focusField(name) {
    var field = fieldFor(name)
    if (field) field.forceActiveFocus()
  }

  function fieldHasFocus(name) {
    var field = fieldFor(name)
    return !!field && field.activeFocus
  }

  function revealListIndex(index) {
    if (itemsListView) itemsListView.positionViewAtIndex(index, ListView.Contain)
  }

  // Whether a login/unlock field has focus; focusAppropriateField() asks.
  function loginFieldHasFocus() {
    return emailField.activeFocus || loginPassField.activeFocus
      || code2faField.activeFocus || deviceCodeField.activeFocus
      || serverUrlField.activeFocus
      || apiClientIdField.activeFocus || apiClientSecretField.activeFocus
      || apiMasterField.activeFocus
  }

  function unlockFieldHasFocus() {
    return unlockForm.passwordField.activeFocus || unlockForm.pinField.activeFocus
  }

  // Re-point each field at its property with Qt.binding, never assign a value:
  // an imperative `text =` breaks the binding, and the field would keep
  // showing text the property no longer holds (a login once went out with no
  // code while the field showed one). See tests/qml/tst_field_binding.qml.
  function syncLoginFields() {
    code2faField.text = Qt.binding(function() { return root.vault.login2faCode })
    deviceCodeField.text = Qt.binding(function() { return root.vault.loginDeviceCode })
    loginPassField.text = Qt.binding(function() { return root.vault.loginPassword })
    apiMasterField.text = Qt.binding(function() { return root.vault.loginPassword })
    apiClientIdField.text = Qt.binding(function() { return root.vault.loginClientId })
    apiClientSecretField.text = Qt.binding(function() { return root.vault.loginClientSecret })
  }

  // Leave a second-factor stage for the credentials form.
  function backToCredentials() {
    root.vault.errorMessage = ""
    root.vault.resetEmailLoginSecondFactor()
    root.vault.invalidateEmailLoginPrewarm()
    Qt.callLater(function() { loginPassField.forceActiveFocus() })
  }

  // The same guarantee for the unlock, item-form and Send secrets.
  function syncSensitiveFields() {
    syncLoginFields()
    unlockForm.syncFromVault()
    sshApprovalPopup.unlockScreen.syncFromVault()
    formPassField.text = Qt.binding(function() { return root.vault.formPassword })
    formNameField.text = Qt.binding(function() { return root.vault.formName })
    sendNameField.text = Qt.binding(function() { return root.vault.sendFormName })
    sendTextField.text = Qt.binding(function() { return root.vault.sendFormText })
    sendPasswordField.text = Qt.binding(function() { return root.vault.sendFormPassword })
  }

  // Visual styles
  readonly property color fg: bar ? bar.foreground : Color.foreground
  readonly property color urgent: bar ? bar.urgent : Color.urgent
  readonly property color accent: Color.accent
  readonly property color dim: Qt.darker(fg, 1.5)
  readonly property color barIconColor: {
    var base = bar ? bar.barForeground : Color.foreground
    if (root.vault.status === "unlocked") return Color.accent
    if (root.vault.status === "locked" || root.vault.status === "checking") return base
    return bar ? bar.urgent : Color.urgent
  }
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family

  // -------------------------------------------------------------------------
  // Vault host
  // -------------------------------------------------------------------------
  //
  // This widget exists per monitor; `vault` is the shared Service.qml, or a
  // private one when the shell does not provide it (see
  // Model.vaultHostDecision()). Never null: until resolved it is the bar's own
  // inert standby vault.
  property var resolvedVault: null
  readonly property var vault: resolvedVault !== null ? resolvedVault : localVault
  // "pending" until decided, then "shared" or "private".
  property string vaultHost: "pending"
  property double vaultResolveStartedMs: 0

  function resolveVault() {
    if (root.resolvedVault) return
    if (root.vaultResolveStartedMs === 0) root.vaultResolveStartedMs = Date.now()
    var host = root.bar ? root.bar.shell : null
    var shared = host && typeof host.serviceFor === "function"
      ? host.serviceFor(root.moduleName) : null
    var decision = Model.vaultHostDecision(!!shared,
      Date.now() - root.vaultResolveStartedMs, Model.vaultHostTimeoutMs())
    if (decision === "wait") return
    root.resolvedVault = decision === "shared" ? shared : localVault
    root.vaultHost = decision
    root.resolvedVault.attachView(root)
  }

  // Polled: serviceFor() is a call, so nothing notifies a binding.
  Timer {
    id: vaultResolveTimer
    interval: 50
    repeat: true
    running: root.resolvedVault === null && root.vaultHost === "pending"
    triggeredOnStart: true
    onTriggered: root.resolveVault()
  }

  onSettingsChanged: if (root.resolvedVault) root.resolvedVault.updateSettings(root.settings)

  // The standby and fallback vault. Inert unless this view attaches to it.
  Service {
    id: localVault
    privateHost: true
  }

  // The bar button and the shell's panel routing call these on the widget.
  function open() { root.vault.open(root) }
  function close() { root.vault.close() }
  function toggle() { root.vault.toggle(root) }

  // Called when another popout replaces this one. If it is this plugin on
  // another monitor, the vault is moving there: close only this copy.
  function closeForPopoutSwitch() {
    root.popoutSwitchClosing = true
    root.hidePopout()
    if (!root.vault.opened) root.vault.close()
    Qt.callLater(function() { root.popoutSwitchClosing = false })
  }

  // A private vault is this view's child and goes with it; the shared one stays.
  Component.onDestruction: if (root.resolvedVault) root.resolvedVault.detachView(root)

  // Width reserved for the overlay scrollbar, so it never covers controls at
  // the right edge. Measured from a real scrollbar, with a floor for before it
  // has a size.
  readonly property real scrollGutter:
    Math.max(settingsScrollBar ? settingsScrollBar.implicitWidth : 0, Style.space(10))

  // The section named by the pinned settings header. Held, not bound: it
  // depends on delegate geometry only known after layout.
  property var settingsStickyEntry: null

  // The settings view's geometry, in one place.
  function settingsViewportTop() { return settingsFlick ? settingsFlick.contentY : 0 }
  function settingsRepeaterItem(i) {
    return settingsRepeater ? settingsRepeater.itemAt(i) : null
  }

  // The section the view is inside: the last heading at or above the top,
  // while its section is still on screen (so the header is named at the start
  // and cleared below the last group). That section's in-list heading is drawn
  // transparent so it does not appear twice.
  function updateSettingsSticky() {
    var entries = root.vault.settingsEntries
    var top = settingsViewportTop()
    var found = null

    for (var i = 0; i < entries.length; i++) {
      if (!entries[i] || entries[i].kind !== "group") continue
      var row = settingsRepeaterItem(i)
      if (!row) continue
      // Still below the top edge: the previous section is current.
      if (row.y > top + 1) break
      if (top < settingsSectionEnd(i)) found = entries[i]
    }
    settingsStickyEntry = found
  }

  // Where the section at `index` ends: the next heading, or the last settings
  // row.
  function settingsSectionEnd(index) {
    var entries = root.vault.settingsEntries
    for (var i = index + 1; i < entries.length; i++) {
      if (!entries[i] || entries[i].kind !== "group") continue
      var next = settingsRepeaterItem(i)
      if (next) return next.y
    }
    for (var j = entries.length - 1; j > index; j--) {
      var last = settingsRepeaterItem(j)
      if (last) return last.y + last.height
    }
    var self = settingsRepeaterItem(index)
    return self ? self.y + self.height : 0
  }

  // "Forget FIDO2 key" on the locked screen, beside Forget Fingerprint.
  component ForgetFidoButton: Button {
    text: "Forget FIDO2 Key"
    iconText: "󰟵"
    tooltipText: "Stop unlocking with this FIDO2 key"
    fontFamily: root.fontFamily
    fontSize: Style.font.caption
    onClicked: root.vault.forgetFidoUnlock()
  }

  // A form row: label, optional caption note, and a NumberField.
  component NumberRow: Row {
    id: numberRow
    property string label: ""
    property string note: ""
    property int value: 0
    property int from: 0
    property int to: 0
    signal modified(int v)

    width: parent ? parent.width : 0
    spacing: Style.space(10)

    Text {
      textFormat: Text.PlainText
      anchors.verticalCenter: parent.verticalCenter
      width: parent.width - Style.space(170)
      text: numberRow.label
      color: root.fg
      font.family: root.fontFamily
      font.pixelSize: Style.font.body
    }
    Text {
      textFormat: Text.PlainText
      anchors.verticalCenter: parent.verticalCenter
      visible: numberRow.note !== ""
      text: numberRow.note
      color: root.dim
      font.family: root.fontFamily
      font.pixelSize: Style.font.caption
    }
    NumberField {
      anchors.verticalCenter: parent.verticalCenter
      value: numberRow.value
      from: numberRow.from
      to: numberRow.to
      stepSize: 1
      foreground: root.fg
      accent: Color.accent
      fontFamily: root.fontFamily
      onModified: function(v) { numberRow.modified(v) }
    }
  }

  // A collapsed vault filter at the foot of the list, showing its name and
  // value (three "All"s alone would be ambiguous). The value is clipped, since
  // Ui.Button cannot elide.
  component VaultFilterButton: Button {
    required property string group
    required property string glyph
    required property string name
    required property string value
    required property string shortcut

    // Clip, then neutralize (plainLabel may add a <span>).
    text: Model.plainLabel(name + ": " + Model.clipLabel(value, 20))
    iconText: root.vault.openFilterGroup === group ? "󰅀" : glyph
    selected: root.vault.openFilterGroup === group
    accent: Color.accent
    fontFamily: root.fontFamily
    fontSize: Style.font.caption
    horizontalPadding: Style.space(10)
    // The full value in the tooltip, neutralized too.
    tooltipText: Model.plainLabel(name + " filter (" + shortcut + "): " + value)
    onClicked: root.vault.toggleFilterGroup(group)
  }

  Component {
    id: shieldIconComp

    Item {
      anchors.fill: parent

      // Constant Base Shield
      TextMetrics {
        id: shieldGlyphMetrics
        font.family: root.fontFamily
        font.pixelSize: Style.bar.iconFont
        text: "󰞀"
      }

      Text {
        id: shieldGlyph
        textFormat: Text.PlainText
        // NativeRendering, like Omarchy's own glyphs; QtRendering fringed the
        // edges with colour.
        anchors.centerIn: parent
        anchors.horizontalCenterOffset: shieldGlyph.implicitWidth / 2
          - (shieldGlyphMetrics.tightBoundingRect.x
            + shieldGlyphMetrics.tightBoundingRect.width / 2)
        text: "󰞀"
        font.family: root.fontFamily
        font.pixelSize: Style.bar.iconFont
        color: root.vault.colorizeIcon ? Color.accent : (bar ? bar.barForeground : Color.foreground)
        renderType: Text.NativeRendering
      }

      // Install badge while a required tool is missing; outranks the padlock.
      Item {
        visible: root.vault.missingRequired.length > 0
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
          text: "󰐕"
          font.family: root.fontFamily
          font.pixelSize: Style.space(8)
          color: bar ? bar.urgent : Color.urgent
          renderType: Text.NativeRendering
        }
      }

      // Mini Padlock Badge in Bottom-Right Corner when locked
      Item {
        visible: root.vault.status === "locked" && root.vault.missingRequired.length === 0
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
  // Bar button
  // -------------------------------------------------------------------------

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    iconComponent: shieldIconComp
    useActiveColor: false
    dimmed: root.vault.status === "unauthenticated" || root.vault.status === "checking"
    tooltipText: {
      // A missing required tool outranks any vault status.
      if (root.vault.missingRequired.length > 0) {
        return "Bitwarden (Click to finish setup)"
      }
      if (root.vault.status === "unlocked") {
        return "Bitwarden (" + (root.vault.items.length > 0 ? root.vault.items.length + " items" : "Unlocked") + ")"
      }
      if (root.vault.status === "locked") {
        return "Bitwarden (Locked)"
      }
      return "Bitwarden (Not Logged In)"
    }
    onPressed: function(buttonCode) {
      if (buttonCode === Qt.RightButton) {
        if (root.vault.status === "unlocked") root.vault.lockVault()
        else root.open()
      } else if (buttonCode === Qt.MiddleButton) {
        root.vault.syncVault()
      } else {
        root.toggle()
      }
    }
  }

  // -------------------------------------------------------------------------
  // Popup window
  // -------------------------------------------------------------------------

  SshApprovalPopup {
    id: sshApprovalPopup
    panel: root
    vault: root.vault
    anchorItem: button
  }

  KeyboardPanel {
    id: panel
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    // The key catcher drives every unlocked screen but the two text-entry
    // ones, and setup (all buttons) outright.
    focusTarget: (root.vault.currentScreen === "setup" || root.vault.currentScreen === "accounts")
      ? keyCatcher
      : ((root.vault.status === "unlocked"
          && root.vault.currentScreen !== "edit"
          && root.vault.currentScreen !== "pin"
          && root.vault.currentScreen !== "fido"
          && root.vault.currentScreen !== "fingerprint")
        ? keyCatcher
        : (root.vault.status === "unauthenticated"
          ? (root.vault.show2faField ? code2faField : emailField)
          : (unlockForm.focusField ? unlockForm.focusField : keyCatcher)))
    contentWidth: panel.fittedContentWidth(Style.space(450))
    contentHeight: panel.fittedContentHeight(mainColumn.implicitHeight, Style.space(640) + root.vault.filterDrawerHeight)

    // Our letter shortcuts get the first look: PanelKeyCatcher would consume
    // h/j/k/l (including l, lock) as navigation.
    Item {
      id: shortcutInterceptor
      Keys.onPressed: function(event) {
        // Escape here, since the catcher is blocked on text-entry screens and
        // would swallow it.
        if (event.key === Qt.Key_Escape && !(event.modifiers & ~Qt.KeypadModifier)) {
          root.vault.handleEscape()
          event.accepted = true
          return
        }

        // Alt may arrive without text; fall back to the key code for A-Z.
        var t = event.text ? String(event.text).toLowerCase() : ""
        if (!t && event.key >= Qt.Key_A && event.key <= Qt.Key_Z) {
          t = String.fromCharCode(event.key).toLowerCase()
        }

        if (event.modifiers & Qt.AltModifier) {
          if (t && root.vault.status === "unlocked" && root.vault.runAltShortcut(t)) event.accepted = true
          return
        }

        if (event.modifiers & ~Qt.KeypadModifier) return
        if (!t || root.vault.currentScreen !== "main") return
        if (root.vault.openFilterGroup !== "") return
        if (t !== "h" && t !== "j" && t !== "k" && t !== "l") return
        if (root.vault.runShortcut(t)) event.accepted = true
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
        || unlockForm.passwordField.activeFocus
        || unlockForm.pinField.activeFocus
        || (root.vault.currentScreen === "edit")
        || (root.vault.currentScreen === "pin")
        || (root.vault.currentScreen === "fido")
        || (root.vault.currentScreen === "fingerprint")
        || (root.vault.currentScreen === "sends" && root.vault.sendMode === "create")

      // Only where the catcher is not blocked; same dispatch as the interceptor.
      onCloseRequested: root.vault.handleEscape()
      onTabRequested: function(direction) {
        if (root.vault.currentScreen === "main") {
          root.vault.cycleCategory(direction)
        } else {
          root.switchPanel(direction)
        }
      }
      onMoveRequested: function(dx, dy) {
        if (root.vault.currentScreen === "sends" && root.vault.sendMode === "list") {
          if (dy !== 0) root.vault.moveSendCursor(dy)
          return
        }
        if (root.vault.currentScreen === "settings") {
          if (dy !== 0) root.vault.moveSettingsCursor(dy)
          else if (dx !== 0) root.vault.adjustSetting(dx)
          return
        }
        if (root.vault.currentScreen === "accounts") {
          if (dy !== 0) root.vault.moveAccountCursor(dy)
          return
        }
        // While a filter drawer is open the arrows drive it, not the item list.
        if (root.vault.openFilterGroup !== "" && root.vault.currentScreen === "main") {
          if (dy !== 0) root.vault.moveFilterCursor(dy)
          return
        }
        if (!root.vault.cursorActive) {
          root.vault.cursorActive = true
          return
        }
        if (root.vault.currentScreen === "main") {
          if (dy !== 0) root.vault.moveCursor(dy)
          else if (dx !== 0) root.vault.cycleCategory(dx)
        }
      }
      onActivateRequested: {
        if (root.vault.currentScreen === "generator" && root.vault.generatorFeedsForm) {
          root.vault.useGeneratedPassword()
          return
        }
        if (root.vault.currentScreen === "sends" && root.vault.sendMode === "list") {
          if (root.vault.sendIndex < root.vault.sends.length) root.vault.copySendLink(root.vault.sends[root.vault.sendIndex])
          return
        }
        if (root.vault.currentScreen === "settings") {
          root.vault.activateSettingRow()
          return
        }
        if (root.vault.currentScreen === "accounts") {
          root.vault.activateAccountRow()
          return
        }
        if (root.vault.openFilterGroup !== "" && root.vault.currentScreen === "main") {
          root.vault.activateFilterOption()
          return
        }
        if (root.vault.currentScreen === "main") {
          var item = root.vault.getSelectedItem()
          if (item) {
            root.vault.handleSmartEnter(item)
          }
          return
        }
        // Enter copies the item's primary secret, like `y`: a login's password,
        // a card's number. Nothing on notes and identities.
        if (root.vault.currentScreen === "detail") {
          if (root.vault.detailIsCard) {
            if (root.vault.detailCard && root.vault.detailCard.number) {
              root.vault.copyToClipboard(root.vault.detailCard.number, "Card number")
            }
          } else if (root.vault.detailIsLoginLike && root.vault.detailPassword) {
            root.vault.copyToClipboard(root.vault.detailPassword, "Password")
          }
        }
      }
      onTextKey: function(key) {
        var lower = String(key).toLowerCase()
        if (root.vault.currentScreen === "sends" && root.vault.sendMode === "list") {
          if (lower === "n") root.vault.beginCreateSend()
          else if (lower === "r") root.vault.loadSends()
          else if (lower === "x" && root.vault.sendIndex < root.vault.sends.length) root.vault.deleteSend(root.vault.sends[root.vault.sendIndex])
          return
        }
        if (root.vault.currentScreen === "main") {
          if (lower === "/") searchField.forceActiveFocus()
          else root.vault.runShortcut(lower)
        } else if (root.vault.currentScreen === "detail") {
          // `y` copies the item's primary secret (password or card number).
          if (lower === "y" || lower === "p") {
            if (root.vault.detailIsCard) {
              if (root.vault.detailCard && root.vault.detailCard.number) root.vault.copyToClipboard(root.vault.detailCard.number, "Card number")
            } else if (root.vault.detailPassword) {
              root.vault.copyToClipboard(root.vault.detailPassword, "Password")
            }
          } else if (lower === "n") {
            if (root.vault.detailIsCard && root.vault.detailCard && root.vault.detailCard.number) {
              root.vault.copyToClipboard(root.vault.detailCard.number, "Card number")
            }
          } else if (lower === "k") {
            if (root.vault.detailIsCard && root.vault.detailCard && root.vault.detailCard.code) {
              root.vault.copyToClipboard(root.vault.detailCard.code, "Security code")
            }
          } else if (lower === "u" || lower === "c") {
            // `u` copies the identifier, `c` the contact address (both the
            // username on a login).
            if (root.vault.detailIsIdentity && root.vault.detailIdentity) {
              if (lower === "c" && root.vault.detailIdentity.email) {
                root.vault.copyToClipboard(root.vault.detailIdentity.email, "Email")
              } else if (root.vault.detailIdentity.username) {
                root.vault.copyToClipboard(root.vault.detailIdentity.username, "Username")
              }
            } else if (root.vault.detailItem && root.vault.detailItem.username) {
              root.vault.copyToClipboard(root.vault.detailItem.username, "Username")
            }
          } else if (lower === "m") {
            if (root.vault.liveTotp) root.vault.copyToClipboard(root.vault.liveTotp, "TOTP")
          } else if (lower === "e") {
            if (root.vault.detailItem) root.vault.startEditItem(root.vault.detailItem)
          } else if (lower === "x") {
            if (root.vault.detailItem && root.vault.detailItem.typeCode !== 5) root.vault.showDeleteConfirm = true
          } else if (lower === "v") {
            if (root.vault.primaryRevealKey !== "") root.vault.toggleFieldReveal(root.vault.primaryRevealKey)
          } else if (lower === "a") {
            root.vault.saveAllAttachments()
          } else if (lower === "b" || lower === "q") {
            root.vault.currentScreen = "main"
          }
        }
      }

      Column {
        id: mainColumn
        anchors.fill: parent
        spacing: Style.space(12)

        // -------------------------------------------------------------------
        // Header
        // -------------------------------------------------------------------
        PanelHero {
          width: parent.width
          title: "Bitwarden"
          meta: {
            if (root.vault.status === "unlocked") {
              if (root.vault.isSyncing) return "Syncing..."
              if (root.vault.isLoading && root.vault.items.length === 0) return "Loading items..."
              // `bw status` can lag the list; show the count meanwhile.
              return root.vault.userEmail || (root.vault.filteredItems.length + " items")
            }
            if (root.vault.status === "locked") return "Vault Locked"
            if (root.vault.status === "checking") return "Checking status..."
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
              visible: root.vault.status === "unlocked" && root.vault.activeScreen === "main"
              iconText: "󰐕"
              tooltipText: "New item (n)"
              fontFamily: root.fontFamily
              onClicked: root.vault.startAddNewItem()
            }

            // Sync Vault Button
            PanelActionButton {
              visible: root.vault.status === "unlocked"
              iconText: "󰑐"
              tooltipText: root.vault.isSyncing ? "Syncing..." : "Sync vault (r)"
              fontFamily: root.fontFamily
              enabled: !root.vault.isSyncing
              onClicked: root.vault.syncVault()
            }

            // Send Button
            PanelActionButton {
              visible: root.vault.status === "unlocked" && root.vault.activeScreen !== "sends"
              iconText: "󰒗"
              tooltipText: "Bitwarden Send (Alt+S)"
              fontFamily: root.fontFamily
              onClicked: root.vault.openSends()
            }

            // Generator Button
            PanelActionButton {
              visible: root.vault.status === "unlocked" && root.vault.activeScreen !== "generator"
              iconText: "󰌆"
              tooltipText: "Password generator (g)"
              fontFamily: root.fontFamily
              onClicked: root.vault.openGenerator()
            }

            // Accounts Button
            PanelActionButton {
              visible: root.vault.activeScreen !== "accounts" && root.vault.activeScreen !== "setup"
                && root.vault.accountsLoaded && (root.vault.accountCount > 1 || root.vault.status !== "unauthenticated")
              iconText: "󰀉"
              tooltipText: "Accounts"
              fontFamily: root.fontFamily
              onClicked: root.vault.openAccounts()
            }

            // Settings Button
            PanelActionButton {
              visible: root.vault.activeScreen !== "settings" && root.vault.activeScreen !== "setup" && root.vault.activeScreen !== "pin"
              iconText: "󰒓"
              tooltipText: "Settings (s)"
              fontFamily: root.fontFamily
              onClicked: root.vault.openSettings()
            }

            // Lock Vault Button
            PanelActionButton {
              visible: root.vault.status === "unlocked"
              iconText: "󰌾"
              tooltipText: "Lock vault (l)"
              fontFamily: root.fontFamily
              onClicked: root.vault.lockVault()
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
        // TOTP follow-up banner
        // -------------------------------------------------------------------
        BorderSurface {
          visible: root.vault.totpFollowupActive && root.vault.totpFollowupItem !== null
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
                text: root.vault.totpFollowupCode ? ("Code: " + root.vault.totpFollowupCode + " (expires in " + root.vault.totpSecRemaining + "s)") : "Fetching 2FA code..."
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
                if (root.vault.totpFollowupItem) root.vault.copyTotpCode(root.vault.totpFollowupItem)
                root.vault.totpFollowupActive = false
              }
            }
          }
        }

        // -------------------------------------------------------------------
        // Development helper banner
        // -------------------------------------------------------------------
        // Shown on every screen while an unverified local build signs.
        BorderSurface {
          visible: root.vault.sshAgentHelper.source === "development" && root.vault.activeScreen !== "settings"
          width: parent.width
          implicitHeight: sshDevHelperText.implicitHeight + Style.space(12)
          color: Util.alpha(Color.urgent, 0.15)
          radius: Style.cornerRadius
          borderSpec: Border.surfaceSpec("menu", "border", Color.urgent, 1)

          Row {
            anchors.centerIn: parent
            width: parent.width - Style.space(16)
            spacing: Style.space(8)
            Text {
              textFormat: Text.PlainText
              text: "󰀪"
              color: Color.urgent
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
            }
            Text {
              id: sshDevHelperText
              textFormat: Text.PlainText
              text: Model.sshAgentDevelopmentHelperWarning(root.vault.sshAgentHelper)
              color: root.fg
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              wrapMode: Text.Wrap
              width: parent.width - Style.space(24)
            }
          }
        }

        // -------------------------------------------------------------------
        // SSH signing cooldown banner
        // -------------------------------------------------------------------
        // On every screen, since refused requests arrive while the panel
        // shows something else; carries the only early resume.
        BorderSurface {
          visible: root.vault.sshCooldownStatus.active
          width: parent.width
          implicitHeight: sshCooldownBannerBody.implicitHeight + Style.space(12)
          color: Util.alpha(Color.urgent, 0.15)
          radius: Style.cornerRadius
          borderSpec: Border.surfaceSpec("menu", "border", Color.urgent, 1)

          Row {
            anchors.centerIn: parent
            width: parent.width - Style.space(16)
            spacing: Style.space(8)
            Text {
              textFormat: Text.PlainText
              text: "󰀪"
              color: Color.urgent
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
            }
            Column {
              id: sshCooldownBannerBody
              width: parent.width - Style.space(24)
              spacing: Style.space(8)

              Text {
                id: sshCooldownBannerText
                textFormat: Text.PlainText
                text: root.vault.sshCooldownStatus.message
                color: root.fg
                font.family: root.fontFamily
                font.pixelSize: Style.font.bodySmall
                wrapMode: Text.Wrap
                width: parent.width
              }

              Button {
                text: "Resume Signing Now"
                iconText: "󰐊"
                tooltipText: "End the cooldown; the next signing request asks again"
                fontFamily: root.fontFamily
                fontSize: Style.font.bodySmall
                onClicked: root.vault.resumeSshSigning()
              }
            }
          }
        }

        // -------------------------------------------------------------------
        // SCREEN 0f: BITWARDEN SEND
        // -------------------------------------------------------------------
        Flickable {
          id: sendFlick
          visible: root.vault.activeScreen === "sends"
          width: parent.width
          height: Math.min(Style.space(520), sendCol.implicitHeight)
          contentWidth: width
          contentHeight: sendCol.implicitHeight
          clip: true
          boundsBehavior: Flickable.StopAtBounds
          flickableDirection: Flickable.VerticalFlick
          ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

          WheelScroll { view: sendFlick }

          Column {
            id: sendCol
            width: sendFlick.width - root.scrollGutter
            spacing: Style.space(10)

            PanelSeparator { width: parent.width }

            Row {
              width: parent.width
              spacing: Style.space(8)

              Button {
                text: root.vault.sendMode === "create" ? "Back to Sends" : "Back (Esc)"
                iconText: "󰁍"
                fontFamily: root.fontFamily
                fontSize: Style.font.bodySmall
                onClicked: {
                  if (root.vault.sendMode === "create") { root.vault.sendError = ""; root.vault.sendMode = "list" }
                  else root.vault.currentScreen = "main"
                }
              }

              Button {
                visible: root.vault.sendMode === "list"
                text: "New Send"
                iconText: "󰐕"
                selected: true
                accent: Color.accent
                fontFamily: root.fontFamily
                fontSize: Style.font.bodySmall
                onClicked: root.vault.beginCreateSend()
              }

              Button {
                visible: root.vault.sendMode === "list"
                text: "Refresh"
                iconText: "󰑐"
                iconSpinning: root.vault.sendsLoading
                fontFamily: root.fontFamily
                fontSize: Style.font.bodySmall
                onClicked: root.vault.loadSends()
              }
            }

            Text {
              textFormat: Text.PlainText
              visible: root.vault.sendError !== ""
              width: parent.width
              text: root.vault.sendError
              color: root.urgent
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              wrapMode: Text.WordWrap
            }

            // ---------------- list ----------------
            Column {
              visible: root.vault.sendMode === "list"
              width: parent.width
              spacing: Style.space(8)

              Text {
                textFormat: Text.PlainText
                visible: !root.vault.sendsLoading && root.vault.sends.length === 0
                width: parent.width
                text: "No Sends yet. A Send shares a secret through a link that expires on its own -- useful for handing someone a credential without it living in a chat log."
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.bodySmall
                wrapMode: Text.WordWrap
              }

              Text {
                textFormat: Text.PlainText
                visible: root.vault.sendsLoading
                text: "Loading Sends..."
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.bodySmall
              }

              Repeater {
                model: root.vault.sends

                delegate: BorderSurface {
                  required property var modelData
                  required property int index
                  width: parent.width
                  implicitHeight: sendRowCol.implicitHeight + Style.space(16)
                  radius: Style.cornerRadius
                  readonly property bool cursored: index === root.vault.sendIndex
                  color: cursored ? Style.hoverFillFor(root.fg, Color.accent) : "transparent"
                  borderSpec: Border.surfaceSpec("menu", "border",
                    cursored ? Color.accent : Qt.rgba(root.fg.r, root.fg.g, root.fg.b, 0.18), 1)

                  MouseArea {
                    anchors.fill: parent
                    hoverEnabled: true
                    onEntered: root.vault.sendIndex = index
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
                      onClicked: root.vault.copySendLink(modelData)
                    }

                    PanelActionButton {
                      anchors.verticalCenter: parent.verticalCenter
                      iconText: "󰆴"
                      tooltipText: "Delete this Send"
                      fontFamily: root.fontFamily
                      enabled: !root.vault.sendBusy
                      onClicked: root.vault.deleteSend(modelData)
                    }
                  }
                }
              }
            }

            // ---------------- create ----------------
            Column {
              visible: root.vault.sendMode === "create"
              width: parent.width
              spacing: Style.space(8)

              Text { textFormat: Text.PlainText; text: "NAME"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
              TextField {
                id: sendNameField
                width: parent.width
                placeholderText: "What is this? (optional)"
                text: root.vault.sendFormName
                onTextChanged: root.vault.sendFormName = text
                enabled: !root.vault.sendBusy
              }

              Text { textFormat: Text.PlainText; text: "TEXT TO SEND"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
              TextField {
                id: sendTextField
                width: parent.width
                placeholderText: "The secret to share..."
                text: root.vault.sendFormText
                onTextChanged: root.vault.sendFormText = text
                enabled: !root.vault.sendBusy
              }

              Row {
                width: parent.width
                spacing: Style.space(6)

                Button {
                  text: "Hide text by default"
                  tooltipText: "The recipient must click to reveal it"
                  selected: root.vault.sendFormHidden
                  accent: Color.accent
                  fontFamily: root.fontFamily
                  fontSize: Style.font.caption
                  onClicked: root.vault.sendFormHidden = !root.vault.sendFormHidden
                }
              }

              NumberRow {
                label: "Delete after"
                note: "days"
                value: root.vault.sendFormDays
                from: 1
                to: 31
                onModified: function(v) { root.vault.sendFormDays = v }
              }

              NumberRow {
                label: "Maximum views"
                note: root.vault.sendFormMaxAccess === 0 ? "unlimited" : ""
                value: root.vault.sendFormMaxAccess
                from: 0
                to: 100
                onModified: function(v) { root.vault.sendFormMaxAccess = v }
              }

              Text { textFormat: Text.PlainText; text: "PASSWORD (OPTIONAL)"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
              TextField {
                id: sendPasswordField
                width: parent.width
                placeholderText: "Recipient must enter this to open the Send..."
                password: true
                text: root.vault.sendFormPassword
                onTextChanged: root.vault.sendFormPassword = text
                enabled: !root.vault.sendBusy
              }

              Button {
                width: parent.width
                text: root.vault.sendBusy ? "Creating..." : "Create Send & Copy Link"
                iconText: root.vault.sendBusy ? "󰑐" : "󰒗"
                iconSpinning: root.vault.sendBusy
                selected: true
                accent: Color.accent
                fontFamily: root.fontFamily
                enabled: !root.vault.sendBusy
                onClicked: root.vault.submitCreateSend()
              }
            }
          }
        }

        // -------------------------------------------------------------------
        // SCREEN 0h: ACCOUNTS
        // -------------------------------------------------------------------
        Column {
          visible: root.vault.activeScreen === "accounts"
          width: parent.width
          spacing: Style.space(10)

          PanelSeparator { width: parent.width }

          Column {
            width: parent.width
            spacing: Style.space(4)

            Text {
              textFormat: Text.PlainText
              text: "Accounts"
              color: root.fg
              font.family: root.fontFamily
              font.pixelSize: Style.font.title
              font.bold: true
            }

            Text {
              textFormat: Text.PlainText
              width: parent.width
              text: "Each account keeps its own sign-in and its own PIN, fingerprint and FIDO2 unlock. "
                + "Only one is unlocked at a time: switching locks the current one."
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              wrapMode: Text.WordWrap
            }
          }

          Repeater {
            model: root.vault.accountRows
            delegate: Button {
              required property var modelData
              required property int index
              width: parent ? parent.width : 0
              text: modelData.label + (modelData.active ? "  (current)" : "")
              iconText: modelData.active ? "󰄬" : "󰀄"
              selected: root.vault.accountIndex === index
              accent: Color.accent
              fontFamily: root.fontFamily
              enabled: root.vault.canChangeAccount()
              onClicked: root.vault.switchAccount(modelData.slot)
            }
          }

          Text {
            textFormat: Text.PlainText
            visible: root.vault.accountRows.length === 0
            width: parent.width
            text: "No accounts yet. Log in to add the first one."
            color: root.dim
            font.family: root.fontFamily
            font.pixelSize: Style.font.bodySmall
            wrapMode: Text.WordWrap
          }

          Row {
            width: parent.width
            spacing: Style.space(8)

            Button {
              text: "Add Account"
              iconText: "󰐕"
              selected: root.vault.accountIndex === root.vault.accountRows.length
              accent: Color.accent
              fontFamily: root.fontFamily
              enabled: root.vault.canChangeAccount() && !root.vault.accountsFull
              onClicked: root.vault.beginAddAccount()
            }

            Button {
              text: "Back"
              iconText: "󰁍"
              fontFamily: root.fontFamily
              onClicked: root.vault.closeAccounts()
            }
          }
        }

        // -------------------------------------------------------------------
        // SCREEN 0e: FINGERPRINT SETUP
        // -------------------------------------------------------------------
        Flickable {
          id: fpFlick
          visible: root.vault.activeScreen === "fingerprint"
          width: parent.width
          height: Math.min(Style.space(520), fpCol.implicitHeight)
          contentWidth: width
          contentHeight: fpCol.implicitHeight
          clip: true
          boundsBehavior: Flickable.StopAtBounds
          flickableDirection: Flickable.VerticalFlick
          ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

          WheelScroll { view: fpFlick }

          Column {
            id: fpCol
            width: fpFlick.width - root.scrollGutter
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
                text: "A fingerprint proves you are present but releases no secret, so it cannot decrypt anything by itself. Your master password is already stored encrypted and sealed to this machine; enabling this adds a way for a verified fingerprint to open it."
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.bodySmall
                wrapMode: Text.WordWrap
              }

              Text {
                textFormat: Text.PlainText
                width: parent.width
                text: "Honest limit: with fingerprint unlock on, a program running as you while you are logged in can open the stored password without your finger. A PIN or a FIDO2 key cannot be bypassed that way."
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
                placeholderText: "Confirm your master password..."
                password: true
                text: root.vault.fpSetupMaster
                onTextChanged: root.vault.fpSetupMaster = text
                onAccepted: root.vault.submitFingerprintSetup()
                enabled: !root.vault.fpBusy
              }

              Text {
                textFormat: Text.PlainText
                visible: root.vault.fpError !== ""
                width: parent.width
                text: root.vault.fpError
                color: root.urgent
                font.family: root.fontFamily
                font.pixelSize: Style.font.bodySmall
                wrapMode: Text.WordWrap
              }

              Row {
                width: parent.width
                spacing: Style.space(8)

                Button {
                  text: root.vault.fpBusy ? "Checking..." : "Enable"
                  iconText: root.vault.fpBusy ? "󰑐" : "󰈷"
                  iconSpinning: root.vault.fpBusy
                  selected: true
                  accent: Color.accent
                  fontFamily: root.fontFamily
                  enabled: !root.vault.fpBusy
                  onClicked: root.vault.submitFingerprintSetup()
                }

                Button {
                  text: "Cancel"
                  iconText: "󰅖"
                  fontFamily: root.fontFamily
                  enabled: !root.vault.fpBusy
                  onClicked: { root.vault.fpError = ""; root.vault.currentScreen = "settings" }
                }
              }
            }
          }
        }

        // -------------------------------------------------------------------
        // SCREEN 0g: FIDO2 SETUP, in FidoSetupScreen.qml.
        // -------------------------------------------------------------------
        FidoSetupScreen {
          panel: root
          vault: root.vault
        }

        // -------------------------------------------------------------------
        // SCREEN 0d: GENERATOR
        // -------------------------------------------------------------------
        Flickable {
          id: genFlick
          visible: root.vault.activeScreen === "generator"
          width: parent.width
          height: Math.min(Style.space(520), genCol.implicitHeight)
          contentWidth: width
          contentHeight: genCol.implicitHeight
          clip: true
          boundsBehavior: Flickable.StopAtBounds
          flickableDirection: Flickable.VerticalFlick
          ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

          WheelScroll { view: genFlick }

          Column {
            id: genCol
            width: genFlick.width - root.scrollGutter
            spacing: Style.space(10)

            PanelSeparator { width: parent.width }

            Row {
              width: parent.width
              spacing: Style.space(8)

              Button {
                text: root.vault.generatorFeedsForm ? "Back to item (Esc)" : "Back (Esc)"
                iconText: "󰁍"
                fontFamily: root.fontFamily
                fontSize: Style.font.bodySmall
                onClicked: root.vault.closeGenerator()
              }

              // Only when opened from the item form: fill its password field
              // and return.
              Button {
                visible: root.vault.generatorFeedsForm
                text: "Use this password (Enter)"
                iconText: "󰄬"
                fontFamily: root.fontFamily
                fontSize: Style.font.bodySmall
                selected: true
                accent: Color.accent
                enabled: !root.vault.genBusy && root.vault.genValue !== ""
                onClicked: root.vault.useGeneratedPassword()
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
                  text: root.vault.genBusy ? "Generating..." : (root.vault.genValue || "-")
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
                  enabled: !root.vault.genBusy
                  onClicked: root.vault.regenerate()
                }

                PanelActionButton {
                  anchors.verticalCenter: parent.verticalCenter
                  iconText: "󰆏"
                  tooltipText: "Copy"
                  fontFamily: root.fontFamily
                  enabled: !root.vault.genBusy && root.vault.genValue !== ""
                  onClicked: root.vault.copyGenerated()
                }
              }
            }

            // Strength meter
            Column {
              width: parent.width
              spacing: Style.space(3)

              readonly property var strength: Model.generatorStrength(root.vault.genOpts)

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
                selected: root.vault.genOpts.type === "password"
                accent: Color.accent
                fontFamily: root.fontFamily
                fontSize: Style.font.bodySmall
                onClicked: root.vault.setGenOpt("type", "password")
              }

              Button {
                text: "Passphrase"
                iconText: "󰈚"
                selected: root.vault.genOpts.type === "passphrase"
                accent: Color.accent
                fontFamily: root.fontFamily
                fontSize: Style.font.bodySmall
                onClicked: root.vault.setGenOpt("type", "passphrase")
              }
            }

            // ---- Password options ----
            Column {
              visible: root.vault.genOpts.type === "password"
              width: parent.width
              spacing: Style.space(8)

              NumberRow {
                label: "Length"
                value: root.vault.genOpts.length
                from: 5
                to: 128
                onModified: function(v) { root.vault.setGenOpt("length", v) }
              }

              Flow {
                width: parent.width
                spacing: Style.space(6)

                Button {
                  text: "A-Z"
                  selected: root.vault.genOpts.uppercase
                  accent: Color.accent
                  fontFamily: root.fontFamily
                  fontSize: Style.font.bodySmall
                  onClicked: root.vault.setGenOpt("uppercase", !root.vault.genOpts.uppercase)
                }
                Button {
                  text: "a-z"
                  selected: root.vault.genOpts.lowercase
                  accent: Color.accent
                  fontFamily: root.fontFamily
                  fontSize: Style.font.bodySmall
                  onClicked: root.vault.setGenOpt("lowercase", !root.vault.genOpts.lowercase)
                }
                Button {
                  text: "0-9"
                  selected: root.vault.genOpts.numbers
                  accent: Color.accent
                  fontFamily: root.fontFamily
                  fontSize: Style.font.bodySmall
                  onClicked: root.vault.setGenOpt("numbers", !root.vault.genOpts.numbers)
                }
                Button {
                  text: "!@#$%^&*"
                  selected: root.vault.genOpts.special
                  accent: Color.accent
                  fontFamily: root.fontFamily
                  fontSize: Style.font.bodySmall
                  onClicked: root.vault.setGenOpt("special", !root.vault.genOpts.special)
                }
                Button {
                  text: "Avoid ambiguous"
                  tooltipText: "Exclude characters that are easy to confuse, such as l, 1, I, O and 0"
                  selected: root.vault.genOpts.ambiguous
                  accent: Color.accent
                  fontFamily: root.fontFamily
                  fontSize: Style.font.bodySmall
                  onClicked: root.vault.setGenOpt("ambiguous", !root.vault.genOpts.ambiguous)
                }
              }

              Row {
                visible: root.vault.genOpts.numbers
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
                  value: root.vault.genOpts.minNumber
                  from: 0
                  to: 9
                  stepSize: 1
                  foreground: root.fg
                  accent: Color.accent
                  fontFamily: root.fontFamily
                  onModified: function(v) { root.vault.setGenOpt("minNumber", v) }
                }
              }

              Row {
                visible: root.vault.genOpts.special
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
                  value: root.vault.genOpts.minSpecial
                  from: 0
                  to: 9
                  stepSize: 1
                  foreground: root.fg
                  accent: Color.accent
                  fontFamily: root.fontFamily
                  onModified: function(v) { root.vault.setGenOpt("minSpecial", v) }
                }
              }
            }

            // ---- Passphrase options ----
            Column {
              visible: root.vault.genOpts.type === "passphrase"
              width: parent.width
              spacing: Style.space(8)

              NumberRow {
                label: "Number of words"
                value: root.vault.genOpts.words
                from: 3
                to: 20
                onModified: function(v) { root.vault.setGenOpt("words", v) }
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
                  text: root.vault.genOpts.separator
                  onTextChanged: if (text && text !== root.vault.genOpts.separator) root.vault.setGenOpt("separator", text.charAt(0))
                }
              }

              Flow {
                width: parent.width
                spacing: Style.space(6)

                Button {
                  text: "Capitalize"
                  selected: root.vault.genOpts.capitalize
                  accent: Color.accent
                  fontFamily: root.fontFamily
                  fontSize: Style.font.bodySmall
                  onClicked: root.vault.setGenOpt("capitalize", !root.vault.genOpts.capitalize)
                }
                Button {
                  text: "Include number"
                  selected: root.vault.genOpts.includeNumber
                  accent: Color.accent
                  fontFamily: root.fontFamily
                  fontSize: Style.font.bodySmall
                  onClicked: root.vault.setGenOpt("includeNumber", !root.vault.genOpts.includeNumber)
                }
              }
            }
          }
        }

        // -------------------------------------------------------------------
        // SCREEN 0c: PIN SETUP (scrolls: taller than the popup on small displays)
        // -------------------------------------------------------------------
        Flickable {
          id: pinFlick
          visible: root.vault.activeScreen === "pin"
          width: parent.width
          height: Math.min(Style.space(520), pinCol.implicitHeight)
          contentWidth: width
          contentHeight: pinCol.implicitHeight
          clip: true
          boundsBehavior: Flickable.StopAtBounds
          flickableDirection: Flickable.VerticalFlick
          ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

          WheelScroll { view: pinFlick }

          Column {
            id: pinCol
            width: pinFlick.width - root.scrollGutter
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
              text: "Your master password is already stored encrypted and sealed to this machine; this adds a way for the PIN "
                + "to open it, through a deliberately slow key derivation. Use " + Model.pinRecommendedLength()
                + " digits or more; " + Model.pinMinLength()
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
              placeholderText: "Confirm your master password..."
              password: true
              text: root.vault.pinSetupMaster
              onTextChanged: root.vault.pinSetupMaster = text
              enabled: !root.vault.pinBusy
            }

            Text {
              textFormat: Text.PlainText
              text: "PIN"
              // The label turns red too, visible while typing in Confirm.
              color: root.vault.pinSetupWeak ? root.urgent : root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              font.bold: true
            }
            TextField {
              id: pinSetupPinField
              width: parent.width
              placeholderText: Model.pinRecommendedLength() + " digits or more..."
              password: true
              text: root.vault.pinSetupPin
              onTextChanged: root.vault.pinSetupPin = text.replace(/[^0-9]/g, "")
              enabled: !root.vault.pinBusy
              // A short PIN is allowed but flagged in red.
              accent: root.vault.pinSetupWeak ? root.urgent : Color.accent
              foreground: root.vault.pinSetupWeak ? root.urgent : root.fg
            }

            Text {
              textFormat: Text.PlainText
              visible: root.vault.pinSetupWeak
              width: parent.width
              text: "󰀪  " + Model.pinWeakWarning(root.vault.pinSetupPin)
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
              text: root.vault.pinSetupConfirm
              onTextChanged: root.vault.pinSetupConfirm = text.replace(/[^0-9]/g, "")
              onAccepted: root.vault.submitPinSetup()
              enabled: !root.vault.pinBusy
            }

            Text {
              textFormat: Text.PlainText
              visible: root.vault.pinError !== ""
              width: parent.width
              text: root.vault.pinError
              color: root.urgent
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              wrapMode: Text.WordWrap
            }

            Row {
              width: parent.width
              spacing: Style.space(8)

              Button {
                text: root.vault.pinBusy ? "Checking..." : "Save PIN"
                iconText: root.vault.pinBusy ? "󰑐" : "󰄬"
                iconSpinning: root.vault.pinBusy
                selected: true
                accent: Color.accent
                fontFamily: root.fontFamily
                enabled: !root.vault.pinBusy
                onClicked: root.vault.submitPinSetup()
              }

              Button {
                text: "Cancel"
                iconText: "󰅖"
                fontFamily: root.fontFamily
                enabled: !root.vault.pinBusy
                onClicked: { root.vault.pinError = ""; root.vault.currentScreen = "settings" }
              }
            }
          }
                  }
        }

        // -------------------------------------------------------------------
        // SCREEN 0a: SETUP WIZARD (missing dependencies; scrolls)
        // -------------------------------------------------------------------
        Flickable {
          id: setupFlick
          visible: root.vault.activeScreen === "setup"
          width: parent.width
          height: Math.min(Style.space(520), setupCol.implicitHeight)
          contentWidth: width
          contentHeight: setupCol.implicitHeight
          clip: true
          boundsBehavior: Flickable.StopAtBounds
          flickableDirection: Flickable.VerticalFlick
          ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

          WheelScroll { view: setupFlick }

          Column {
            id: setupCol
            width: setupFlick.width - root.scrollGutter
          spacing: Style.space(12)

          PanelSeparator { width: parent.width }

          Column {
            width: parent.width
            spacing: Style.space(4)

            Text {
              textFormat: Text.PlainText
              text: root.vault.missingRequired.length > 0 ? "One more step" : "All set"
              color: root.fg
              font.family: root.fontFamily
              font.pixelSize: Style.font.title
              font.bold: true
            }

            Text {
              textFormat: Text.PlainText
              width: parent.width
              text: root.vault.missingRequired.length > 0
                ? "The plugin drives these tools rather than bundling them. Install the required ones below and the panel picks them up on its own -- no terminal work to come back from."
                : "Every required tool is installed. Optional ones below unlock extra features."
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              wrapMode: Text.WordWrap
            }
          }

          Repeater {
            // Only rows this machine can act on (no reader, no fingerprint row).
            model: Model.applicableDependencies(root.vault.dependencies)

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

                  Text {
                    textFormat: Text.PlainText
                    visible: !!modelData.note
                    width: parent.width
                    text: modelData.note
                    color: root.urgent
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                    wrapMode: Text.WordWrap
                  }

                  // A setup row needs more than the package (an enrolled
                  // finger, the PAM stack); only the setup command does that.
                  Text {
                    textFormat: Text.PlainText
                    visible: modelData.setup && modelData.installed && !modelData.ready
                    width: parent.width
                    text: "Reader stack is installed, but no finger is enrolled yet."
                    color: root.urgent
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                    wrapMode: Text.WordWrap
                  }
                }

                // One button per row, whichever door this row goes through.
                Button {
                  anchors.verticalCenter: parent.verticalCenter
                  visible: modelData.setup ? !modelData.ready : !modelData.installed
                  text: modelData.setup ? "Set up" : "Install"
                  iconText: modelData.setup ? "󰈷" : "󰐕"
                  tooltipText: modelData.setup
                    ? "omarchy setup security fingerprint"
                    : "omarchy install app " + modelData.pkg
                  fontFamily: root.fontFamily
                  fontSize: Style.font.caption
                  onClicked: root.vault.installOne(modelData)
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
              onClicked: root.vault.checkDependencies()
            }

            // Installs every missing package, optional ones included.
            Button {
              visible: root.vault.installablePackages.length > 0
              text: root.vault.installablePackages.length > 1 ? "Install all missing" : "Install"
              iconText: "󰐕"
              selected: true
              accent: Color.accent
              tooltipText: "omarchy install app " + root.vault.installablePackages.join(" ")
              fontFamily: root.fontFamily
              fontSize: Style.font.bodySmall
              onClicked: root.vault.installMissing()
            }

            Button {
              text: root.vault.missingRequired.length > 0 ? "Continue anyway" : "Done"
              iconText: "󰁍"
              fontFamily: root.fontFamily
              fontSize: Style.font.bodySmall
              onClicked: root.vault.dismissSetup()
            }
          }
                  }
        }

        // -------------------------------------------------------------------
        // SCREEN 0b: SETTINGS (scrolls)
        // -------------------------------------------------------------------
        Column {
          id: settingsScreen
          visible: root.vault.activeScreen === "settings"
          width: parent.width
          spacing: Style.space(10)

          PanelSeparator { width: parent.width }

          // Pinned above the scroll area: the current section (click to fold
          // it from anywhere inside) and the way out.
          Item {
            width: parent.width
            height: Style.space(26)

            // An indicator, not a control.
            Row {
              id: stickySection
              anchors.left: parent.left
              anchors.verticalCenter: parent.verticalCenter
              spacing: Style.space(6)
              visible: root.settingsStickyEntry !== null

              PanelSectionHeader {
                textFormat: Text.PlainText
                anchors.verticalCenter: parent.verticalCenter
                text: root.settingsStickyEntry
                  ? String(root.settingsStickyEntry.label || "").toUpperCase() : ""
                foreground: root.fg
                fontFamily: root.fontFamily
              }
            }

            Row {
              anchors.right: parent.right
              // Clear of the scrollbar, aligned with the rows below.
              anchors.rightMargin: root.scrollGutter
              anchors.verticalCenter: parent.verticalCenter
              spacing: Style.space(8)

              Text {
                textFormat: Text.PlainText
                anchors.verticalCenter: parent.verticalCenter
                visible: root.vault.settingsFlash !== ""
                text: "󰄬 " + root.vault.settingsFlash
                color: Color.accent
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
              }

              Button {
                text: "Back (Esc)"
                iconText: "󰁍"
                fontFamily: root.fontFamily
                fontSize: Style.font.bodySmall
                onClicked: root.vault.closeSettings()
              }
            }
          }


          Flickable {
            id: settingsFlick
            width: parent.width
            height: Math.min(Style.space(520), settingsCol.implicitHeight)
            contentWidth: width
            contentHeight: settingsCol.implicitHeight
            clip: true
            boundsBehavior: Flickable.StopAtBounds
            flickableDirection: Flickable.VerticalFlick
            ScrollBar.vertical: ScrollBar {
              id: settingsScrollBar
              policy: ScrollBar.AsNeeded
            }

            WheelScroll { view: settingsFlick }

            // Recompute the pinned section as the view moves or resizes (the
            // resize a frame later, after layout).
            onContentYChanged: root.updateSettingsSticky()
            onContentHeightChanged: Qt.callLater(root.updateSettingsSticky)

            Column {
              id: settingsCol
              // Clear of the overlay scrollbar, reserved unconditionally so
              // rows do not reflow as it appears.
              width: settingsFlick.width - root.scrollGutter
            spacing: Style.space(10)

            Connections {
              target: root.vault
              function onSettingsIndexChanged() {
                var row = settingsRepeater.itemAt(root.vault.settingsIndex)
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
              model: root.vault.settingsEntries

              delegate: Column {
                required property var modelData
                required property int index
                width: parent.width
                spacing: Style.space(4)
                readonly property bool cursored: index === root.vault.settingsIndex

                readonly property bool isGroup: modelData.kind === "group"

              // The heading the pinned bar is showing collapses, and the one it
              // replaces reappears at once, so the content height is stable.
              readonly property bool yieldsToBar: isGroup
                && Boolean(root.settingsStickyEntry)
                && root.settingsStickyEntry.group === modelData.group

                // Breathing room above each heading, except the first.
                Item {
                  visible: isGroup && index > 0 && !yieldsToBar
                  width: parent.width
                  height: visible ? Style.space(18) : 0
                }

                // Headings are rows of their own so the pinned bar can find
                // them by delegate geometry.
                Item {
                  visible: isGroup && !yieldsToBar
                  width: parent.width
                  height: visible ? Style.space(22) : 0

                  PanelSectionHeader {
                    textFormat: Text.PlainText
                    anchors.left: parent.left
                    anchors.verticalCenter: parent.verticalCenter
                    text: String(modelData.label || "").toUpperCase()
                    foreground: root.fg
                    fontFamily: root.fontFamily
                  }
                }

                // Inert when its dependency is missing, with the reason shown.
                readonly property bool blocked: !isGroup && root.vault.settingBlocked(modelData)

                Item {
                  visible: !isGroup
                  width: parent.width
                  implicitHeight: visible
                    ? Math.max(settingTextCol.implicitHeight, settingControlRow.implicitHeight, Style.space(32))
                    : 0

                  // Keyboard cursor: a bar in the gutter.
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
                      // `|| ""`: also evaluated for heading rows, which have no
                      // description.
                      text: blocked
                        ? root.vault.settingBlockedReason(modelData)
                        : (modelData.description || "")
                          + (root.vault.settingNote(modelData) ? "\n\n" + root.vault.settingNote(modelData) : "")
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
                      checked: modelData.type === "bool" && root.vault.settingValue(modelData)
                      interactive: !blocked
                      foreground: root.fg
                      accent: Color.accent
                      onToggled: {
                        if (blocked) return
                        // A PIN must be chosen, with the master password.
                        if (modelData.action === "pin") {
                          if (checked) root.vault.disablePinUnlock()
                          else root.vault.beginPinSetup()
                          return
                        }
                        if (modelData.action === "fingerprint") {
                          if (checked) root.vault.forgetFingerprintUnlock()
                          else root.vault.beginFingerprintSetup()
                          return
                        }
                        if (modelData.action === "fido") {
                          if (checked) root.vault.forgetFidoUnlock()
                          else root.vault.beginFidoSetup()
                          return
                        }
                        root.vault.writeSetting(modelData.key, !checked, "bool")
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
                      value: modelData.type === "int" ? root.vault.settingValue(modelData) : 0
                      from: modelData.min || 0
                      to: modelData.max || 100
                      stepSize: modelData.step || 1
                      foreground: root.fg
                      accent: Color.accent
                      fontFamily: root.fontFamily
                      onModified: function(v) { root.vault.writeSetting(modelData.key, v, "int") }
                    }
                  }
                }

                Text {
                  textFormat: Text.PlainText
                  visible: modelData.type === "int" && root.vault.settingValue(modelData) === 0 && !!modelData.zeroLabel
                  text: (modelData.zeroLabel || "") + " -- this is disabled."
                  color: root.urgent
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                }

                PanelSeparator { width: parent.width }

                // The SSH agent's status and routing block, loaded at the end
                // of its group so folding the section hides it. A Loader, since
                // only one delegate wants it.
                Loader {
                  width: parent.width
                  active: !isGroup && modelData.group === "sshAgent"
                    && modelData.lastInGroup === true
                  visible: active
                  sourceComponent: SshAgentSettings { panel: root; vault: root.vault }
                }
              }
            }

            Item { width: parent.width; height: Style.space(18) }

            PanelSectionHeader {
              textFormat: Text.PlainText
              text: "MAINTENANCE"
              foreground: root.fg
              fontFamily: root.fontFamily
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
                  root.vault.setupDismissed = false
                  root.vault.checkDependencies()
                  root.vault.currentScreen = "setup"
                }
              }

              Button {
                visible: root.vault.fingerprintStored
                text: "Forget Fingerprint"
                iconText: "󰈷"
                tooltipText: "Stop unlocking with fingerprint"
                fontFamily: root.fontFamily
                fontSize: Style.font.bodySmall
                onClicked: root.vault.forgetFingerprintUnlock()
              }
            }

            // Its own row: a third button would elide a label.
            Row {
              width: parent.width
              spacing: Style.space(8)

              Button {
                visible: root.vault.fidoStored
                text: "Forget FIDO2 Key"
                iconText: "󰟵"
                tooltipText: "Stop unlocking with this FIDO2 key"
                fontFamily: root.fontFamily
                fontSize: Style.font.bodySmall
                onClicked: root.vault.forgetFidoUnlock()
              }
            }

            // Destructive actions below, set apart.
            Item { width: parent.width; height: Style.space(18) }

            PanelSeparator { width: parent.width }

            PanelSectionHeader {
              textFormat: Text.PlainText
              text: "DANGER ZONE"
              foreground: Color.urgent
              fontFamily: root.fontFamily
            }

            // Its own row: with the confirmation's buttons it would overflow
            // and elide "Remove Plugin Data".
            Row {
              width: parent.width
              spacing: Style.space(8)

              Button {
                visible: !root.vault.pluginDataConfirmPending
                text: "Remove Plugin Data"
                iconText: "󰩹"
                tooltipText: "Clear the keyring entries, learned suggestions and exported public keys this plugin stored"
                fontFamily: root.fontFamily
                fontSize: Style.font.bodySmall
                enabled: !root.vault.pluginDataBusy
                onClicked: root.vault.beginPluginDataRemoval()
              }

              Button {
                visible: root.vault.pluginDataConfirmPending
                text: "Remove Everything"
                iconText: "󰩹"
                fontFamily: root.fontFamily
                fontSize: Style.font.bodySmall
                enabled: !root.vault.pluginDataBusy
                onClicked: root.vault.beginPluginDataRemoval()
              }

              Button {
                visible: root.vault.pluginDataConfirmPending
                text: "Cancel"
                fontFamily: root.fontFamily
                fontSize: Style.font.bodySmall
                onClicked: root.vault.cancelPluginDataRemoval()
              }
            }

            // Must run before removal: `omarchy plugin remove` has no
            // uninstall hook.
            Text {
              textFormat: Text.PlainText
              width: parent.width
              visible: root.vault.pluginDataConfirmPending
              text: "This clears the stored master password, learned suggestions and exported public keys. "
                + "Settings and your vault are untouched. It cannot be undone."
              color: root.urgent
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              wrapMode: Text.WordWrap
            }

            Text {
              textFormat: Text.PlainText
              width: parent.width
              visible: root.vault.pluginDataFlash !== ""
              text: root.vault.pluginDataFlash
              color: root.fg
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              wrapMode: Text.WordWrap
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
        }

        // An SSH request waiting on an unlock, shown above the unlock controls.
        Column {
          // Stays through the key load that follows the unlock.
          visible: !root.vault.sshAgentApprovalPopup && root.vault.sshUnlockRequest !== null
            && (root.vault.status === "locked" || root.vault.sshAgentLoadActive)
          width: parent.width
          spacing: Style.space(6)

          PanelSeparator { width: parent.width }

          Text {
            textFormat: Text.PlainText
            width: parent.width
            text: "󰌆  An SSH key is needed"
            color: Color.accent
            font.family: root.fontFamily
            font.pixelSize: Style.font.body
          }

          SshCaption {
            panel: root
            text: !root.vault.sshUnlockRequest
              ? ""
              : (root.vault.sshUnlockRequest.keyName !== ""
                  ? root.vault.sshUnlockRequest.keyName + " · requested by "
                    + root.vault.sshUnlockRequest.processName
                  // A listing names no key; it asks which keys exist.
                  : root.vault.sshUnlockRequest.processName
                    + " is asking which SSH keys are available")
            color: root.fg
          }

          SshCaption {
            panel: root
            text: root.vault.sshAgentLoadActive
              ? Model.sshAgentLoadingNote()
              : "Unlocking loads your keys. You will still be asked before anything is signed."
          }

          Row {
            width: parent.width
            spacing: Style.space(8)

            Button {
              visible: !root.vault.sshAgentLoadActive
              text: "Not now (Esc)"
              iconText: "󰅘"
              fontFamily: root.fontFamily
              fontSize: Style.font.caption
              onClicked: root.vault.denySshRequest()
            }

            Text {
              textFormat: Text.PlainText
              anchors.verticalCenter: parent.verticalCenter
              text: root.vault.sshPromptRemainingSec + "s left"
              color: root.vault.sshPromptRemainingSec <= 5 ? root.urgent : root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
            }
          }
        }

        // SCREEN: SSH signing approval, in SshApprovalScreen.qml.
        SshApprovalScreen {
          panel: root
          vault: root.vault
          active: !root.vault.sshAgentApprovalPopup && root.vault.activeScreen === "sshApproval"
        }

        // -------------------------------------------------------------------
        // SCREEN 1: LOGIN (unauthenticated)
        // -------------------------------------------------------------------
        Column {
          visible: root.vault.status === "unauthenticated" && root.vault.activeScreen !== "settings" && root.vault.activeScreen !== "setup" && root.vault.activeScreen !== "pin" && root.vault.activeScreen !== "fido" && root.vault.activeScreen !== "fingerprint"
            && root.vault.activeScreen !== "accounts"
          width: parent.width
          spacing: Style.space(12)

          PanelSeparator { width: parent.width }

          // Adding an account: say so, and offer the way back.
          Row {
            visible: root.vault.addingAccount || root.vault.accountCount > 0
            width: parent.width
            spacing: Style.space(8)

            Text {
              textFormat: Text.PlainText
              anchors.verticalCenter: parent.verticalCenter
              width: parent.width - accountBackBtn.width - Style.space(8)
              text: root.vault.addingAccount ? "Sign in to add another account." : "This account is signed out."
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              elide: Text.ElideRight
            }

            Button {
              id: accountBackBtn
              text: root.vault.addingAccount && root.vault.slotBeforeAdd !== "" ? "Cancel" : "Accounts"
              iconText: root.vault.addingAccount && root.vault.slotBeforeAdd !== "" ? "󰅖" : "󰀉"
              fontFamily: root.fontFamily
              fontSize: Style.font.caption
              enabled: root.vault.canChangeAccount()
              onClicked: root.vault.addingAccount && root.vault.slotBeforeAdd !== ""
                ? root.vault.cancelAddAccount() : root.vault.openAccounts()
            }
          }

          Row {
            anchors.horizontalCenter: parent.horizontalCenter
            spacing: Style.space(8)

            Button {
              text: "Email & Password"
              iconText: "󰇮"
              selected: root.vault.loginMethod === "email"
              fontFamily: root.fontFamily
              fontSize: Style.font.caption
              onClicked: {
                root.vault.invalidateEmailLoginPrewarm()
                root.vault.resetEmailLoginSecondFactor()
                root.vault.loginMethod = "email"
              }
            }

            Button {
              text: "API Key"
              iconText: "󰌋"
              selected: root.vault.loginMethod === "apikey"
              fontFamily: root.fontFamily
              fontSize: Style.font.caption
              onClicked: {
                root.vault.invalidateEmailLoginPrewarm()
                root.vault.resetEmailLoginSecondFactor()
                root.vault.loginMethod = "apikey"
              }
            }
          }

          Column {
            visible: root.vault.loginMethod !== "email" || root.vault.loginCredentialsStage
            width: parent.width
            spacing: Style.space(5)

            Text {
              textFormat: Text.PlainText
              text: "SERVER REGION"
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              font.bold: true
            }

            Row {
              anchors.horizontalCenter: parent.horizontalCenter
              spacing: Style.space(6)

              Button {
                text: "US"
                selected: root.vault.loginServerRegion === "us"
                fontFamily: root.fontFamily
                fontSize: Style.font.caption
                onClicked: root.vault.selectLoginServerRegion("us")
              }

              Button {
                text: "EU"
                selected: root.vault.loginServerRegion === "eu"
                fontFamily: root.fontFamily
                fontSize: Style.font.caption
                onClicked: root.vault.selectLoginServerRegion("eu")
              }

              Button {
                text: "Custom"
                selected: root.vault.loginServerRegion === "custom"
                fontFamily: root.fontFamily
                fontSize: Style.font.caption
                onClicked: root.vault.selectLoginServerRegion("custom")
              }
            }

            TextField {
              id: serverUrlField
              visible: root.vault.loginServerRegion === "custom"
              width: parent.width
              placeholderText: "https://vault.example.com"
              text: root.vault.loginServerUrl
              onTextChanged: root.vault.loginServerUrl = text
              onTextEdited: {
                root.vault.loginServerUrl = text
                root.vault.resetEmailLoginSecondFactor()
                root.vault.invalidateEmailLoginPrewarm()
              }
            }
          }

          // METHOD A: Email & Password
          Column {
            visible: root.vault.loginMethod === "email"
            width: parent.width
            spacing: Style.space(10)

            Column {
              visible: root.vault.loginCredentialsStage
              width: parent.width
              spacing: Style.space(3)
              Text { textFormat: Text.PlainText; text: "EMAIL ADDRESS"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
              TextField {
                id: emailField
                width: parent.width
                placeholderText: "you@example.com"
                text: root.vault.loginEmail
                onTextChanged: root.vault.loginEmail = text
                onTextEdited: {
                  root.vault.loginEmail = text
                  root.vault.resetEmailLoginSecondFactor()
                  root.vault.invalidateEmailLoginPrewarm()
                }
                onAccepted: loginPassField.forceActiveFocus()
              }
            }

            Column {
              visible: root.vault.loginCredentialsStage
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
                  text: root.vault.loginPassword
                  onTextChanged: root.vault.loginPassword = text
                  onTextEdited: {
                    root.vault.loginPassword = text
                    if (root.vault.show2faField) {
                      root.vault.resetEmailLoginSecondFactor()
                      root.vault.invalidateEmailLoginPrewarm()
                    }
                  }
                  onActiveFocusChanged: {
                    if (activeFocus) root.vault.prepareEmailLogin()
                  }
                  onAccepted: root.vault.show2faField ? code2faField.forceActiveFocus() : root.vault.submitLogin()
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

            // New-device verification: bw takes this code only from a prompt;
            // see deviceVerificationLoginCommand().
            Column {
              visible: root.vault.showDeviceCodeField
              width: parent.width
              spacing: Style.space(3)

              Text {
                textFormat: Text.PlainText
                text: "NEW DEVICE VERIFICATION"
                color: Color.accent
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                font.bold: true
              }

              Text {
                textFormat: Text.PlainText
                width: parent.width
                text: "Bitwarden has not seen this machine before and emailed a code to "
                  + "your login address. This is asked once per device."
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                wrapMode: Text.WordWrap
              }

              TextField {
                id: deviceCodeField
                width: parent.width
                placeholderText: "Code from your email..."
                text: root.vault.loginDeviceCode
                onTextChanged: root.vault.loginDeviceCode = text
                onAccepted: root.vault.submitDeviceVerification()
              }

              Button {
                width: parent.width
                text: root.vault.isLoading ? "Verifying device..." : "Verify Device & Unlock"
                iconText: root.vault.isLoading ? "󰑐" : "󰌋"
                iconSpinning: root.vault.isLoading
                selected: true
                accent: Color.accent
                fontFamily: root.fontFamily
                enabled: !root.vault.isLoading
                onClicked: root.vault.submitDeviceVerification()
              }

              Row {
                width: parent.width
                spacing: Style.space(6)

                Button {
                  text: "Back to credentials"
                  iconText: "󰁍"
                  fontFamily: root.fontFamily
                  fontSize: Style.font.caption
                  onClicked: root.backToCredentials()
                }

                // A real terminal can answer anything this path cannot.
                Button {
                  text: "Use Terminal Instead"
                  iconText: "󰞷"
                  fontFamily: root.fontFamily
                  fontSize: Style.font.caption
                  onClicked: root.vault.launchTerminalLogin()
                }
              }
            }

            // bw's method question (asked when several are usable). The pick is
            // sent before any code is typed.
            Column {
              visible: root.vault.show2faMethodPicker
              width: parent.width
              spacing: Style.space(6)

              Text {
                textFormat: Text.PlainText
                text: "TWO-STEP METHOD"
                color: Color.accent
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                font.bold: true
              }

              Text {
                textFormat: Text.PlainText
                width: parent.width
                text: "Which one do you use for this account? Bitwarden is asked for a code "
                  + "only after you choose, and the choice is remembered for next time."
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                wrapMode: Text.WordWrap
              }

              Repeater {
                model: Model.twoFactorMethods()

                Column {
                  width: parent.width
                  spacing: Style.space(2)

                  Button {
                    width: parent.width
                    text: modelData.label
                    iconText: "󰌋"
                    fontFamily: root.fontFamily
                    enabled: !root.vault.isLoading
                    onClicked: root.vault.chooseTwoFactorMethod(modelData.method)
                  }

                  Text {
                    textFormat: Text.PlainText
                    width: parent.width
                    text: modelData.hint
                    color: root.dim
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                    wrapMode: Text.WordWrap
                  }
                }
              }

              Button {
                text: "Back to credentials"
                iconText: "󰁍"
                fontFamily: root.fontFamily
                fontSize: Style.font.caption
                onClicked: root.backToCredentials()
              }
            }

            // Bitwarden tells us whether this account needs a second factor.
            Column {
              visible: root.vault.show2faField
              width: parent.width
              spacing: Style.space(3)

              Text {
                textFormat: Text.PlainText
                text: root.vault.login2faMethodLabel
                  ? "TWO-STEP CODE (" + root.vault.login2faMethodLabel.toUpperCase() + ")"
                  : "TWO-STEP VERIFICATION CODE (2FA)"
                color: Color.accent
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                font.bold: true
              }

              TextField {
                id: code2faField
                width: parent.width
                placeholderText: "6-digit Authenticator / Email verification code..."
                text: root.vault.login2faCode
                onTextChanged: {
                  root.vault.login2faCode = text
                  root.vault.invalidateEmailLoginPrewarm()
                }
                onAccepted: root.vault.submitLogin()
              }

              Row {
                width: parent.width
                spacing: Style.space(6)

                Button {
                  text: "Back to credentials"
                  iconText: "󰁍"
                  fontFamily: root.fontFamily
                  fontSize: Style.font.caption
                  onClicked: root.backToCredentials()
                }

                // The only way back to the question once remembered.
                Button {
                  text: "Change method"
                  iconText: "󰑐"
                  fontFamily: root.fontFamily
                  fontSize: Style.font.caption
                  onClicked: {
                    root.vault.invalidateEmailLoginPrewarm()
                    root.vault.reopenTwoFactorMethodPicker()
                  }
                }
              }
            }

            Button {
              // For the stages that use the ordinary login command.
              visible: !root.vault.show2faMethodPicker && !root.vault.showDeviceCodeField
              width: parent.width
              text: root.vault.emailLoginButtonText()
              iconText: root.vault.logoutCleanupFailed ? "󰑐" : ((root.vault.logoutPending || root.vault.isLoading) ? "󰑐" : "󰌋")
              iconSpinning: !root.vault.logoutCleanupFailed && (root.vault.logoutPending || root.vault.isLoading)
              selected: true
              accent: Color.accent
              fontFamily: root.fontFamily
              enabled: root.vault.logoutCleanupFailed || (!root.vault.logoutPending && !root.vault.isLoading)
              onClicked: root.vault.logoutCleanupFailed ? root.vault.retryLogoutCleanup() : root.vault.submitLogin()
            }
          }

          // METHOD B: API Key
          Column {
            visible: root.vault.loginMethod === "apikey"
            width: parent.width
            spacing: Style.space(10)

            Column {
              width: parent.width
              spacing: Style.space(3)
              Text { textFormat: Text.PlainText; text: "CLIENT ID"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
              TextField {
                id: apiClientIdField
                width: parent.width
                placeholderText: "user.xxxxxxxx-xxxx-xxxx..."
                text: root.vault.loginClientId
                onTextChanged: root.vault.loginClientId = text
              }
            }

            Column {
              width: parent.width
              spacing: Style.space(3)
              Text { textFormat: Text.PlainText; text: "CLIENT SECRET"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
              TextField {
                id: apiClientSecretField
                width: parent.width
                placeholderText: "Client secret string..."
                password: true
                text: root.vault.loginClientSecret
                onTextChanged: root.vault.loginClientSecret = text
              }
            }

            Column {
              width: parent.width
              spacing: Style.space(3)
              Text { textFormat: Text.PlainText; text: "MASTER PASSWORD"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
              TextField {
                id: apiMasterField
                width: parent.width
                placeholderText: "Master password to unlock vault..."
                password: true
                text: root.vault.loginPassword
                onTextChanged: root.vault.loginPassword = text
                onAccepted: root.vault.submitLogin()
              }
            }

            Button {
              width: parent.width
              text: root.vault.logoutCleanupFailed ? "Retry Logout Cleanup" : (root.vault.logoutPending ? "Finishing logout..." : (root.vault.isLoading ? "Logging in..." : "Log In with API Key"))
              iconText: root.vault.logoutCleanupFailed ? "󰑐" : ((root.vault.logoutPending || root.vault.isLoading) ? "󰑐" : "󰌋")
              iconSpinning: !root.vault.logoutCleanupFailed && (root.vault.logoutPending || root.vault.isLoading)
              selected: true
              accent: Color.accent
              fontFamily: root.fontFamily
              enabled: root.vault.logoutCleanupFailed || (!root.vault.logoutPending && !root.vault.isLoading)
              onClicked: root.vault.logoutCleanupFailed ? root.vault.retryLogoutCleanup() : root.vault.submitLogin()
            }
          }

          // The terminal login; prominent when device verification needs it.
          Row {
            anchors.horizontalCenter: parent.horizontalCenter
            spacing: Style.space(6)
            Text {
              textFormat: Text.PlainText
              text: root.vault.loginDeviceVerification
                ? "Device verification needs a terminal:"
                : "Prefer interactive TTY login?"
              color: root.vault.loginDeviceVerification ? Color.accent : root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              font.bold: root.vault.loginDeviceVerification
              anchors.verticalCenter: parent.verticalCenter
            }
            Button {
              text: root.vault.loginDeviceVerification ? "Finish in Terminal" : "Launch Terminal"
              iconText: "󰞷"
              selected: root.vault.loginDeviceVerification
              accent: Color.accent
              fontFamily: root.fontFamily
              fontSize: Style.font.caption
              onClicked: root.vault.launchTerminalLogin()
            }
          }
        }

        // -------------------------------------------------------------------
        // SCREEN 2: LOCKED VIEW (logged in, vault locked)
        // -------------------------------------------------------------------
        Column {
          visible: (root.vault.status === "locked" || root.vault.status === "checking")
            && root.vault.currentScreen !== "settings" && root.vault.currentScreen !== "setup" && root.vault.currentScreen !== "pin" && root.vault.currentScreen !== "fido" && root.vault.currentScreen !== "fingerprint"
            && root.vault.currentScreen !== "accounts"
          width: parent.width
          spacing: Style.space(14)

          PanelSeparator { width: parent.width }

          UnlockForm {
            id: unlockForm
            panel: root
            vault: root.vault
          }

          Row {
            anchors.horizontalCenter: parent.horizontalCenter
            spacing: Style.space(8)

            Button {
              text: root.vault.accountCount > 1 ? "Switch Account" : "Add Account"
              iconText: "󰀉"
              tooltipText: root.vault.accountCount > 1
                ? "Unlock another account; each keeps its own unlock methods"
                : "Sign in to another account beside this one"
              fontFamily: root.fontFamily
              fontSize: Style.font.caption
              enabled: root.vault.canChangeAccount()
              onClicked: root.vault.accountCount > 1 ? root.vault.openAccounts() : root.vault.beginAddAccount()
            }

            Button {
              text: "Log Out"
              iconText: "󰍃"
              tooltipText: "Sign this account out and forget its unlock methods"
              fontFamily: root.fontFamily
              fontSize: Style.font.caption
              onClicked: root.vault.logoutAccount()
            }
          }

          // This account's presence methods, on their own row.
          Row {
            visible: root.vault.fingerprintStored || root.vault.fidoStored
            anchors.horizontalCenter: parent.horizontalCenter
            spacing: Style.space(8)

            Button {
              visible: root.vault.fingerprintStored
              text: "Forget Fingerprint"
              iconText: "󰈷"
              tooltipText: "Stop unlocking this account with fingerprint"
              fontFamily: root.fontFamily
              fontSize: Style.font.caption
              onClicked: root.vault.forgetFingerprintUnlock()
            }

            ForgetFidoButton {
              visible: root.vault.fidoStored
            }
          }
        }

        // -------------------------------------------------------------------
        // SCREEN 3: ITEM LIST
        // -------------------------------------------------------------------
        Column {
          visible: root.vault.status === "unlocked" && root.vault.activeScreen === "main"
          width: parent.width
          spacing: Style.space(8)

          // Search Field
          Row {
            width: parent.width
            spacing: Style.space(6)

            TextField {
              id: searchField
              width: parent.width - (root.vault.searchQuery ? clearSearchBtn.width + Style.space(6) : 0)
              placeholderText: "Search items, usernames, URLs, public keys, fingerprints..."
              text: root.vault.searchQuery
              onTextChanged: {
                root.vault.searchQuery = text
                root.vault.selectedIndex = 0
                root.vault.closeFilterGroup()
                root.vault.scheduleFilterRebuild()
              }
              // Alt+letter runs the same shortcuts without leaving the box.
              Keys.onPressed: function(event) {
                if (!(event.modifiers & Qt.AltModifier)) return
                if (!event.text) return
                if (root.vault.runAltShortcut(String(event.text).toLowerCase())) {
                  event.accepted = true
                }
              }
              Keys.onDownPressed: {
                keyCatcher.forceActiveFocus()
                root.vault.moveCursor(1)
              }
              Keys.onReturnPressed: {
                var itm = root.vault.getSelectedItem()
                if (itm) root.vault.handleSmartEnter(itm)
              }
              // Only while the list is showing: Qt keeps focus on hidden
              // items, so Escape from the item form would close the panel.
              Keys.onEscapePressed: function(event) {
                if (root.vault.currentScreen !== "main") {
                  event.accepted = false   // let it reach the panel's dispatch
                  return
                }
                if (text) text = ""
                else root.vault.handleEscape()
              }
            }

            PanelActionButton {
              id: clearSearchBtn
              visible: root.vault.searchQuery !== ""
              iconText: "󰅖"
              tooltipText: "Clear search"
              fontFamily: root.fontFamily
              onClicked: searchField.text = ""
            }
          }

          // Contextual Suggestion Banner
          BorderSurface {
            visible: Boolean(root.vault.suggestedItems.length > 0 && !root.vault.suggestionsDismissed && root.vault.searchQuery.trim() === "" && root.vault.detectedContext && root.vault.detectedContext.displayName)
            width: parent.width
            implicitHeight: Style.space(28)
            radius: Style.cornerRadius
            color: Style.selectedFillFor(root.fg, Color.accent)
            borderSpec: Border.controlSpec("normal", Color.accent, Color.accent)

            // A RowLayout, so the label (a window title) takes whatever width
            // is left.
            RowLayout {
              anchors.fill: parent
              anchors.leftMargin: Style.space(8)
              anchors.rightMargin: Style.space(6)
              spacing: Style.space(6)

              Text {
                textFormat: Text.PlainText
                Layout.alignment: Qt.AlignVCenter
                text: "󰌠"
                color: Color.accent
                font.family: root.fontFamily
                font.pixelSize: Style.font.bodySmall
              }

              Text {
                textFormat: Text.PlainText
                Layout.alignment: Qt.AlignVCenter
                Layout.fillWidth: true
                // "Title", not "site": a page writes its own title, so this
                // names what the title says, never a verified address.
                text: "Matches window title: " + (root.vault.detectedContext ? root.vault.detectedContext.displayName : "active window")
                color: Color.accent
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                font.bold: true
                elide: Text.ElideRight
              }

              PanelActionButton {
                Layout.alignment: Qt.AlignVCenter
                iconText: "󰅖"
                tooltipText: "Dismiss suggestion"
                fontFamily: root.fontFamily
                size: Style.space(18)
                fontSize: Style.font.caption
                onClicked: {
                  root.vault.suggestionsDismissed = true
                  root.vault.rebuildFilter()
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
              model: root.vault.filteredItems
              spacing: Style.space(4)
              boundsBehavior: Flickable.StopAtBounds
              reuseItems: true
              currentIndex: root.vault.selectedIndex
              ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

              WheelScroll { view: itemsListView }

              delegate: BorderSurface {
                id: itemRow
                required property var modelData
                required property int index

                readonly property var itemData: modelData
                readonly property bool isSelected: root.vault.cursorActive && root.vault.selectedIndex === index
                readonly property bool isHovered: rowMouseArea.containsMouse

                width: ListView.view.width - root.scrollGutter
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

                  // The type glyph, spinning while the row is being saved.
                  Text {
                    textFormat: Text.PlainText
                    anchors.verticalCenter: parent.verticalCenter
                    text: itemData.pending ? "󰑐" : Model.itemTypeGlyph(itemData.typeCode)
                    color: itemData.pending
                      ? root.dim
                      : (itemData.favorite ? Color.accent : root.fg)
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.title
                    width: Style.space(20)
                    // Centred so it spins on its own axis.
                    horizontalAlignment: Text.AlignHCenter
                    transformOrigin: Item.Center

                    RotationAnimation on rotation {
                      running: Boolean(itemData.pending)
                      loops: Animation.Infinite
                      from: 0
                      to: 360
                      duration: 900
                    }
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

                      // Attachments badge; names are in the detail view.
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
                        text: root.vault.learnedIds[itemData.id] ? "󰐾 Suggested" : "󰌠 Suggested"
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
                        id: rowSubtitle
                        textFormat: Text.PlainText
                        text: itemData.subtitle || Model.itemTypeLabel(itemData.typeCode)
                        color: root.dim
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.caption
                        elide: Text.ElideRight
                        // Only what it needs, so the folder tag keeps its place.
                        width: Math.min(implicitWidth,
                          parent.width
                            - (itemData.organizationId ? Style.space(40) : 0)
                            - (itemData.isSuggested ? Style.space(75) : 0)
                            - (rowFolderTag.visible ? Style.space(90) : 0))
                      }

                      Text {
                        id: rowFolderTag
                        textFormat: Text.PlainText
                        // Only worth showing when it is not already implied by the filter.
                        visible: Boolean(itemData.folderId) && root.vault.selectedFolder === "all"
                        text: "· 󰉋 " + Model.folderName(root.vault.folders, itemData.folderId)
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
                      visible: itemData.typeCode !== 5 && itemData.hasPassword
                      iconText: "󰌆"
                      tooltipText: "Copy password (Enter / y)"
                      fontFamily: root.fontFamily
                      onClicked: root.vault.handleSmartEnter(itemData)
                    }

                    PanelActionButton {
                      visible: itemData.typeCode !== 5 && itemData.username !== ""
                      iconText: ""
                      tooltipText: "Copy username (u)"
                      fontFamily: root.fontFamily
                      onClicked: root.vault.copyUsername(itemData)
                    }

                    PanelActionButton {
                      visible: itemData.typeCode !== 5 && itemData.hasTotp
                      iconText: "󰥔"
                      tooltipText: "Copy TOTP code (m)"
                      fontFamily: root.fontFamily
                      onClicked: root.vault.copyTotpCode(itemData)
                    }

                    PanelActionButton {
                      iconText: "󰏫"
                      tooltipText: itemData.typeCode === 5 ? "View public key" : "View / Edit item (e)"
                      fontFamily: root.fontFamily
                      onClicked: root.vault.openDetail(itemData)
                    }

                    PanelActionButton {
                      visible: itemData.typeCode !== 5 && itemData.uris && itemData.uris.length > 0
                      iconText: "󰖟"
                      tooltipText: "Open URL (w)"
                      fontFamily: root.fontFamily
                      onClicked: root.vault.openUrl(itemData.uris[0])
                    }
                  }
                }

                MouseArea {
                  id: rowMouseArea
                  anchors.fill: parent
                  hoverEnabled: true
                  cursorShape: Qt.PointingHandCursor
                  onClicked: {
                    root.vault.cursorActive = true
                    root.vault.openFilterGroup = ""
                    root.vault.selectedIndex = index
                    root.vault.openDetail(itemData)
                  }
                }
              }
            }

            // Empty state overlay
            Item {
              visible: root.vault.filteredItems.length === 0
              anchors.fill: parent

              Column {
                anchors.centerIn: parent
                spacing: Style.space(6)

                Text {
                  textFormat: Text.PlainText
                  anchors.horizontalCenter: parent.horizontalCenter
                  text: root.vault.isLoading && root.vault.items.length === 0 ? "󰑐" : (root.vault.items.length === 0 ? "󰞀" : "󰍡")
                  color: root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.space(36)
                  RotationAnimation on rotation {
                    running: root.vault.isLoading && root.vault.items.length === 0
                    from: 0
                    to: 360
                    duration: 900
                    loops: Animation.Infinite
                  }
                }

                Text {
                  textFormat: Text.PlainText
                  anchors.horizontalCenter: parent.horizontalCenter
                  text: root.vault.isLoading && root.vault.items.length === 0
                    ? "Loading items..."
                    : root.vault.emptyListMessage()
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
          // Each collapsed button opens a list in place; the item list gives
          // back that height, so the panel does not jump.

          PanelSeparator { width: parent.width }

          // The open group: a pinned header, then up to five scrolling rows.
          Column {
            id: filterDrawer
            width: parent.width
            height: root.vault.filterDrawerHeight
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
                text: root.vault.openFilterGroup === "folders" ? "󰉋"
                    : root.vault.openFilterGroup === "organizations" ? "󰦑"
                    : "󰀻"
                color: Color.accent
                font.family: root.fontFamily
                font.pixelSize: Style.font.bodySmall
              }

              Text {
                textFormat: Text.PlainText
                anchors.verticalCenter: parent.verticalCenter
                text: root.vault.openFilterGroup === "folders" ? "FOLDERS"
                    : root.vault.openFilterGroup === "organizations" ? "ORGANIZATIONS"
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
                visible: root.vault.currentFilterOptions.length > root.vault.currentFilterVisibleRows
                text: root.vault.currentFilterOptions.length + " total"
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
              }
            }

            Flickable {
              id: filterOptionsList
              width: parent.width
              height: Math.min(root.vault.currentFilterVisibleRows, root.vault.currentFilterOptions.length) * root.vault.filterRowHeight
              contentWidth: width
              contentHeight: filterOptionsCol.implicitHeight
              clip: true
              boundsBehavior: Flickable.StopAtBounds
              flickableDirection: Flickable.VerticalFlick
              ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

              WheelScroll { view: filterOptionsList }

              // Keep the keyboard cursor in view when it runs past the fold.
              function revealCursor() {
                var y = root.vault.filterOptionIndex * root.vault.filterRowHeight
                if (y < contentY) contentY = y
                else if (y + root.vault.filterRowHeight > contentY + height) {
                  contentY = y + root.vault.filterRowHeight - height
                }
              }

              Connections {
                target: root.vault
                function onFilterOptionIndexChanged() { filterOptionsList.revealCursor() }
              }

              Column {
                id: filterOptionsCol
                width: filterOptionsList.width - root.scrollGutter
                spacing: 0

                Repeater {
                  model: root.vault.currentFilterOptions

                  delegate: BorderSurface {
                    required property var modelData
                    required property int index
                    width: filterOptionsCol.width
                    implicitHeight: root.vault.filterRowHeight
                    radius: Style.cornerRadius
                    readonly property bool cursored: index === root.vault.filterOptionIndex
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
                      onEntered: root.vault.filterOptionIndex = index
                      onClicked: root.vault.applyFilterOption(root.vault.openFilterGroup, modelData.id)
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

          // The three collapsed filter buttons. A Flow, since vault names make
          // their widths unpredictable and a Row would overflow the panel: one
          // centred line normally, two when needed. `width` reads implicit
          // widths only, so it never depends on its own result.
          Flow {
            anchors.horizontalCenter: parent.horizontalCenter
            spacing: Style.space(6)
            readonly property real naturalWidth: folderFilterButton.implicitWidth
              + organizationFilterButton.implicitWidth
              + typeFilterButton.implicitWidth
              + spacing * 2
            width: Math.min(parent.width, naturalWidth)

            VaultFilterButton {
              id: folderFilterButton
              group: "folders"
              glyph: "󰉋"
              name: "Folders"
              value: root.vault.folderFilterLabel()
              shortcut: "f"
            }

            VaultFilterButton {
              id: organizationFilterButton
              group: "organizations"
              glyph: "󰦑"
              name: "Organizations"
              value: root.vault.organizationFilterLabel()
              shortcut: "o"
            }

            VaultFilterButton {
              id: typeFilterButton
              group: "types"
              glyph: "󰀻"
              name: "Types"
              value: root.vault.typeFilterLabel()
              shortcut: "t"
            }
          }

        }

        // -------------------------------------------------------------------
        // SCREEN 4: ITEM DETAIL
        // -------------------------------------------------------------------
        Column {
          visible: root.vault.status === "unlocked" && root.vault.activeScreen === "detail"
          width: parent.width
          spacing: Style.space(12)

          // Back and actions. A Flow, since the suggestion button appears at
          // runtime and the panel can be narrower than asked; it wraps rather
          // than pushing Delete off the edge.
          Flow {
            width: parent.width
            spacing: Style.space(8)

            Button {
              // Short, like the Sends screen's.
              text: "Back (Esc)"
              iconText: "󰁍"
              fontFamily: root.fontFamily
              fontSize: Style.font.bodySmall
              onClicked: root.vault.currentScreen = "main"
            }

            Button {
              visible: Boolean(root.vault.detectedContext && root.vault.detectedContext.displayName && root.vault.detailItem && root.vault.detailItem.typeCode !== 5)
              readonly property bool pinned: Boolean(root.vault.detailItem
                && Model.isAssociated(root.vault.associations, root.vault.detectedContext, root.vault.detailItem.id))
              text: pinned ? "Suggested here" : "Suggest here"
              iconText: pinned ? "󰐾" : "󰐽"
              selected: pinned
              accent: Color.accent
              // Window titles are untrusted; tooltips auto-detect markup.
              tooltipText: Model.plainLabel((pinned ? "Stop suggesting this for " : "Always suggest this for ")
                + (root.vault.detectedContext ? root.vault.detectedContext.displayName : ""))
              fontFamily: root.fontFamily
              fontSize: Style.font.bodySmall
              onClicked: root.vault.toggleAssociation(root.vault.detailItem)
            }

            Button {
              visible: Boolean(root.vault.detailItem && root.vault.detailItem.typeCode !== 5)
              text: "Edit"
              iconText: "󰏫"
              fontFamily: root.fontFamily
              fontSize: Style.font.bodySmall
              onClicked: if (root.vault.detailItem) root.vault.startEditItem(root.vault.detailItem)
            }

            Button {
              visible: Boolean(root.vault.detailItem && root.vault.detailItem.typeCode !== 5)
              text: "Delete"
              iconText: "󰆴"
              accent: Color.urgent
              fontFamily: root.fontFamily
              fontSize: Style.font.bodySmall
              onClicked: root.vault.showDeleteConfirm = true
            }
          }

          // Delete Confirmation Banner
          BorderSurface {
            visible: root.vault.showDeleteConfirm
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
                onClicked: root.vault.deleteCurrentItem()
              }

              Button {
                text: "Cancel"
                fontFamily: root.fontFamily
                fontSize: Style.font.caption
                onClicked: root.vault.showDeleteConfirm = false
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

            WheelScroll { view: detailFlickable }

            Column {
              id: detailContentColumn
              width: detailFlickable.width - root.scrollGutter
              spacing: Style.space(12)

              // Item Header
              Row {
                width: parent.width
                spacing: Style.space(10)

                Text {
                  textFormat: Text.PlainText
                  anchors.verticalCenter: parent.verticalCenter
                  text: root.vault.detailItem ? Model.itemTypeGlyph(root.vault.detailItem.typeCode) : "󰌋"
                  color: (root.vault.detailItem && root.vault.detailItem.favorite) ? Color.accent : root.fg
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
                      text: root.vault.detailItem ? root.vault.detailItem.name : "Loading..."
                      color: root.fg
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.title
                      font.bold: true
                      elide: Text.ElideRight
                      width: Math.min(implicitWidth, parent.width - Style.space(20))
                    }

                    Text {
                      textFormat: Text.PlainText
                      visible: Boolean(root.vault.detailItem && root.vault.detailItem.favorite)
                      text: "★"
                      color: Color.accent
                      font.pixelSize: Style.font.body
                    }
                  }

                  Row {
                    spacing: Style.space(6)
                    Text {
                      textFormat: Text.PlainText
                      text: root.vault.detailItem ? Model.itemTypeLabel(root.vault.detailItem.typeCode) : ""
                      color: root.dim
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.caption
                    }
                    Text {
                      textFormat: Text.PlainText
                      visible: Boolean(root.vault.detailItem && root.vault.detailItem.organizationId)
                      text: "• Shared Organization"
                      color: Color.accent
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.caption
                    }
                    Text {
                      textFormat: Text.PlainText
                      visible: Boolean(root.vault.detailItem && root.vault.detailItem.folderId)
                      text: root.vault.detailItem
                        ? "• 󰉋 " + Model.folderName(root.vault.folders, root.vault.detailItem.folderId)
                        : ""
                      color: root.dim
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.caption
                    }
                  }
                }
              }

              // FIELD: Public SSH key (type 5 is deliberately read-only)
              Column {
                visible: Boolean(root.vault.detailItem && root.vault.detailItem.typeCode === 5)
                width: parent.width
                spacing: Style.space(4)
                PanelSectionHeader { text: "PUBLIC KEY" }
                BorderSurface {
                  width: parent.width
                  implicitHeight: Math.max(Style.space(54), sshPublicKeyText.implicitHeight + Style.space(20))
                  radius: Style.cornerRadius
                  color: Style.hoverFillFor(root.fg, Color.accent)
                  borderSpec: Border.controlSpec("normal", root.fg, Color.accent)
                  Text {
                    id: sshPublicKeyText
                    textFormat: Text.PlainText
                    anchors.fill: parent
                    anchors.margins: Style.space(10)
                    text: root.vault.detailItem ? (root.vault.detailItem.publicKey || "No public key") : ""
                    color: root.fg
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                    wrapMode: Text.WrapAnywhere
                  }
                }
                Text {
                  textFormat: Text.PlainText
                  visible: Boolean(root.vault.detailItem && root.vault.detailItem.fingerprint)
                  text: "Fingerprint: " + (root.vault.detailItem ? root.vault.detailItem.fingerprint : "")
                  color: root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  wrapMode: Text.WrapAnywhere
                }
              }

              // FIELD: Username
              DetailField {
                visible: root.vault.detailIsLoginLike && Boolean(root.vault.detailItem) && root.vault.detailItem.username !== ""
                label: "Username / Email"
                copyLabel: "Username"
                shortcutHint: "u"
                copyIcon: ""
                value: root.vault.detailItem ? root.vault.detailItem.username : ""
                foreground: root.fg
                fontFamily: root.fontFamily
                onCopyRequested: root.vault.copyToClipboard(root.vault.detailItem ? root.vault.detailItem.username : "", "Username")
              }

              // FIELD: Password
              Column {
                visible: root.vault.detailIsLoginLike && Boolean(root.vault.detailItem) && (root.vault.detailPassword !== "" || root.vault.detailItem.hasPassword)
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
                      text: root.vault.isFieldRevealed("password")
                        ? root.vault.detailPassword : Model.maskString(root.vault.detailPassword || "password")
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
                        iconText: root.vault.isFieldRevealed("password") ? "󰈉" : "󰈈"
                        tooltipText: root.vault.isFieldRevealed("password") ? "Hide password (v)" : "Reveal password (v)"
                        fontFamily: root.fontFamily
                        onClicked: root.vault.toggleFieldReveal("password")
                      }

                      PanelActionButton {
                        iconText: "󰌆"
                        tooltipText: "Copy password (y / Enter)"
                        fontFamily: root.fontFamily
                        onClicked: root.vault.copyToClipboard(root.vault.detailPassword, "Password")
                      }
                    }
                  }
                }
              }

              // FIELD: TOTP (2FA Code)
              Column {
                visible: root.vault.detailIsLoginLike && Boolean(root.vault.detailItem) && root.vault.detailItem.hasTotp
                width: parent.width
                spacing: Style.space(4)

                RowLayout {
                  width: parent.width
                  PanelSectionHeader { text: "VERIFICATION CODE (TOTP)" }
                  Item { Layout.fillWidth: true }
                  Text {
                    textFormat: Text.PlainText
                    text: root.vault.totpSecRemaining + "s"
                    color: Color.accent
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                    font.bold: true
                    Layout.alignment: Qt.AlignVCenter
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
                    width: parent.width * (root.vault.totpSecRemaining / 30.0)
                    color: Color.accent
                  }

                  Row {
                    anchors.fill: parent
                    anchors.leftMargin: Style.space(12)
                    anchors.rightMargin: Style.space(6)

                    Text {
                      textFormat: Text.PlainText
                      anchors.verticalCenter: parent.verticalCenter
                      text: root.vault.liveTotp ? (root.vault.liveTotp.length === 6 ? root.vault.liveTotp.slice(0, 3) + " " + root.vault.liveTotp.slice(3) : root.vault.liveTotp) : "Loading..."
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
                      enabled: root.vault.liveTotp !== ""
                      onClicked: root.vault.copyToClipboard(root.vault.liveTotp, "TOTP code")
                    }
                  }
                }
              }

              // FIELD: Website / URIs
              Column {
                visible: root.vault.detailIsLoginLike && Boolean(root.vault.detailItem) && root.vault.detailItem.uris && root.vault.detailItem.uris.length > 0
                width: parent.width
                spacing: Style.space(4)

                PanelSectionHeader { text: "WEBSITE" }

                Repeater {
                  model: root.vault.detailItem ? root.vault.detailItem.uris : []
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
                        onClicked: root.vault.openUrl(modelData)
                      }
                    }
                  }
                }
              }

              // FIELD: Attachments. Listed from the item's metadata; bytes are
              // fetched on request. Above NOTES, which grows with its text and
              // would push the files below the fold.
              Column {
                visible: Boolean(root.vault.detailItem && root.vault.detailItem.typeCode !== 5 && root.vault.detailItem.hasAttachments)
                width: parent.width
                spacing: Style.space(4)

                RowLayout {
                  width: parent.width
                  spacing: Style.space(6)
                  PanelSectionHeader { text: "ATTACHMENTS" }
                  Item { Layout.fillWidth: true }
                  PanelActionButton {
                    visible: Boolean(root.vault.detailItem && root.vault.detailItem.attachments
                      && root.vault.detailItem.attachments.length > 1)
                    iconText: "󰇚"
                    tooltipText: "Save all attachments (a)"
                    size: Style.space(20)
                    fontFamily: root.fontFamily
                    onClicked: root.vault.saveAllAttachments()
                  }
                }

                Repeater {
                  model: root.vault.detailItem ? root.vault.detailItem.attachments : []
                  delegate: BorderSurface {
                    readonly property string savedPath: root.vault.attachmentSavedPath(modelData.id)
                    readonly property bool busy: root.vault.attachmentBusyId === modelData.id
                    readonly property bool queued: root.vault.isAttachmentQueued(modelData.id)

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
                        id: attachmentGlyph
                        textFormat: Text.PlainText
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
                        id: attachmentStatus
                        textFormat: Text.PlainText
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
                          onClicked: root.vault.queueAttachment(modelData)
                        }

                        PanelActionButton {
                          visible: savedPath !== ""
                          iconText: "󰏌"
                          tooltipText: "Open the saved file"
                          fontFamily: root.fontFamily
                          onClicked: root.vault.openSavedAttachment(modelData.id)
                        }

                        PanelActionButton {
                          visible: savedPath !== ""
                          iconText: "󰝰"
                          // Our own path, still drawn as text.
                          tooltipText: Model.plainLabel("Show in " + Model.parentDirectory(savedPath))
                          fontFamily: root.fontFamily
                          onClicked: root.vault.revealSavedAttachment(modelData.id)
                        }
                      }
                    }
                  }
                }
              }

              // FIELD: Notes
              Column {
                visible: Boolean(root.vault.detailItem && root.vault.detailItem.typeCode !== 5 && root.vault.detailItem.notes !== "")
                width: parent.width
                spacing: Style.space(4)

                RowLayout {
                  width: parent.width
                  PanelSectionHeader { text: "NOTES" }
                  Item { Layout.fillWidth: true }
                  PanelActionButton {
                    iconText: "󰈙"
                    tooltipText: "Copy notes"
                    size: Style.space(20)
                    fontFamily: root.fontFamily
                    onClicked: if (root.vault.detailItem) root.vault.copyToClipboard(root.vault.detailItem.notes, "Notes")
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
                    textFormat: Text.PlainText
                    anchors.fill: parent
                    anchors.margins: Style.space(10)
                    text: root.vault.detailItem ? root.vault.detailItem.notes : ""
                    color: root.fg
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.bodySmall
                    wrapMode: Text.Wrap
                  }
                }
              }

              // -----------------------------------------------------------
              // FIELDS: Card
              // -----------------------------------------------------------
              // Expiry shown as one value.
              DetailField {
                visible: root.vault.detailIsCard
                label: "Cardholder Name"
                value: root.vault.detailCard ? root.vault.detailCard.cardholderName : ""
                foreground: root.fg
                fontFamily: root.fontFamily
                onCopyRequested: root.vault.copyToClipboard(root.vault.detailCard ? root.vault.detailCard.cardholderName : "", "Cardholder name")
              }

              DetailField {
                visible: root.vault.detailIsCard
                label: "Brand"
                value: root.vault.detailCard ? root.vault.detailCard.brand : ""
                foreground: root.fg
                fontFamily: root.fontFamily
                onCopyRequested: root.vault.copyToClipboard(root.vault.detailCard ? root.vault.detailCard.brand : "", "Brand")
              }

              DetailField {
                visible: root.vault.detailIsCard
                label: "Card Number"
                copyLabel: "Card number"
                shortcutHint: "n / Enter"
                revealHint: "v"
                sensitive: true
                revealed: root.vault.isFieldRevealed("cardNumber")
                value: root.vault.detailCard ? root.vault.detailCard.number : ""
                foreground: root.fg
                fontFamily: root.fontFamily
                onRevealToggled: root.vault.toggleFieldReveal("cardNumber")
                onCopyRequested: root.vault.copyToClipboard(root.vault.detailCard ? root.vault.detailCard.number : "", "Card number")
              }

              DetailField {
                visible: root.vault.detailIsCard
                label: "Expires"
                value: root.vault.detailCardExpiry
                foreground: root.fg
                fontFamily: root.fontFamily
                onCopyRequested: root.vault.copyToClipboard(root.vault.detailCardExpiry, "Expiry")
              }

              DetailField {
                visible: root.vault.detailIsCard
                label: "Security Code"
                copyLabel: "Security code"
                shortcutHint: "k"
                sensitive: true
                revealed: root.vault.isFieldRevealed("cardCode")
                value: root.vault.detailCard ? root.vault.detailCard.code : ""
                foreground: root.fg
                fontFamily: root.fontFamily
                onRevealToggled: root.vault.toggleFieldReveal("cardCode")
                onCopyRequested: root.vault.copyToClipboard(root.vault.detailCard ? root.vault.detailCard.code : "", "Security code")
              }

              // -----------------------------------------------------------
              // FIELDS: Identity
              // -----------------------------------------------------------
              // Every field is declared; DetailField hides the empty ones.
              DetailField {
                visible: root.vault.detailIsIdentity
                label: "Name"
                value: root.vault.detailIdentityName
                foreground: root.fg
                fontFamily: root.fontFamily
                onCopyRequested: root.vault.copyToClipboard(root.vault.detailIdentityName, "Name")
              }

              DetailField {
                visible: root.vault.detailIsIdentity
                label: "Username"
                shortcutHint: "u"
                value: root.vault.detailIdentity ? root.vault.detailIdentity.username : ""
                foreground: root.fg
                fontFamily: root.fontFamily
                onCopyRequested: root.vault.copyToClipboard(root.vault.detailIdentity ? root.vault.detailIdentity.username : "", "Username")
              }

              DetailField {
                visible: root.vault.detailIsIdentity
                label: "Company"
                value: root.vault.detailIdentity ? root.vault.detailIdentity.company : ""
                foreground: root.fg
                fontFamily: root.fontFamily
                onCopyRequested: root.vault.copyToClipboard(root.vault.detailIdentity ? root.vault.detailIdentity.company : "", "Company")
              }

              DetailField {
                visible: root.vault.detailIsIdentity
                label: "Email"
                shortcutHint: "c"
                value: root.vault.detailIdentity ? root.vault.detailIdentity.email : ""
                foreground: root.fg
                fontFamily: root.fontFamily
                onCopyRequested: root.vault.copyToClipboard(root.vault.detailIdentity ? root.vault.detailIdentity.email : "", "Email")
              }

              DetailField {
                visible: root.vault.detailIsIdentity
                label: "Phone"
                value: root.vault.detailIdentity ? root.vault.detailIdentity.phone : ""
                foreground: root.fg
                fontFamily: root.fontFamily
                onCopyRequested: root.vault.copyToClipboard(root.vault.detailIdentity ? root.vault.detailIdentity.phone : "", "Phone")
              }

              // Masked like a password (and unlike one, not rotatable).
              DetailField {
                visible: root.vault.detailIsIdentity
                label: "Social Security Number"
                copyLabel: "SSN"
                sensitive: true
                revealed: root.vault.isFieldRevealed("ssn")
                value: root.vault.detailIdentity ? root.vault.detailIdentity.ssn : ""
                foreground: root.fg
                fontFamily: root.fontFamily
                onRevealToggled: root.vault.toggleFieldReveal("ssn")
                onCopyRequested: root.vault.copyToClipboard(root.vault.detailIdentity ? root.vault.detailIdentity.ssn : "", "SSN")
              }

              DetailField {
                visible: root.vault.detailIsIdentity
                label: "Passport Number"
                copyLabel: "Passport number"
                sensitive: true
                revealed: root.vault.isFieldRevealed("passport")
                value: root.vault.detailIdentity ? root.vault.detailIdentity.passportNumber : ""
                foreground: root.fg
                fontFamily: root.fontFamily
                onRevealToggled: root.vault.toggleFieldReveal("passport")
                onCopyRequested: root.vault.copyToClipboard(root.vault.detailIdentity ? root.vault.detailIdentity.passportNumber : "", "Passport number")
              }

              DetailField {
                visible: root.vault.detailIsIdentity
                label: "Licence Number"
                copyLabel: "Licence number"
                sensitive: true
                revealed: root.vault.isFieldRevealed("licence")
                value: root.vault.detailIdentity ? root.vault.detailIdentity.licenseNumber : ""
                foreground: root.fg
                fontFamily: root.fontFamily
                onRevealToggled: root.vault.toggleFieldReveal("licence")
                onCopyRequested: root.vault.copyToClipboard(root.vault.detailIdentity ? root.vault.detailIdentity.licenseNumber : "", "Licence number")
              }

              PanelSectionHeader {
                visible: root.vault.detailIsIdentity && root.vault.detailIdentityAddress !== ""
                text: "ADDRESS"
              }

              // One block, not seven rows. An address is copied as an address.
              BorderSurface {
                visible: root.vault.detailIsIdentity && root.vault.detailIdentityAddress !== ""
                width: parent.width
                implicitHeight: addressText.implicitHeight + Style.space(16)
                radius: Style.cornerRadius
                color: Style.hoverFillFor(root.fg, Color.accent)
                borderSpec: Border.controlSpec("normal", root.fg, Color.accent)

                Row {
                  anchors.fill: parent
                  anchors.margins: Style.space(8)
                  spacing: Style.space(6)

                  Text {
                    id: addressText
                    textFormat: Text.PlainText
                    anchors.verticalCenter: parent.verticalCenter
                    text: root.vault.detailIdentityAddress
                    color: root.fg
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.body
                    wrapMode: Text.Wrap
                    width: parent.width - copyAddressBtn.width - Style.space(10)
                  }

                  PanelActionButton {
                    id: copyAddressBtn
                    anchors.verticalCenter: parent.verticalCenter
                    iconText: "󰈙"
                    tooltipText: "Copy address"
                    fontFamily: root.fontFamily
                    onClicked: root.vault.copyToClipboard(root.vault.detailIdentityAddress, "Address")
                  }
                }
              }

              // -----------------------------------------------------------
              // FIELDS: Custom
              // -----------------------------------------------------------
              // Hidden fields use the same per-field reveal and copy as the
              // built-in secrets.
              Column {
                id: customFieldsSection
                visible: Boolean(root.vault.detailItem && root.vault.detailItem.fields
                  && root.vault.detailItem.fields.length > 0)
                width: parent.width
                spacing: Style.space(8)

                PanelSectionHeader { text: "CUSTOM FIELDS" }

                Repeater {
                  id: customFieldRepeater
                  model: root.vault.detailItem ? root.vault.detailItem.fields : []

                  delegate: DetailField {
                    required property var modelData
                    required property int index
                    readonly property string revealKey: "customField:" + index

                    label: modelData.name
                    copyLabel: modelData.name
                    value: modelData.value
                    sensitive: Boolean(modelData.sensitive)
                    revealed: root.vault.isFieldRevealed(revealKey)
                    foreground: root.fg
                    fontFamily: root.fontFamily
                    onRevealToggled: root.vault.toggleFieldReveal(revealKey)
                    onCopyRequested: root.vault.copyToClipboard(modelData.value, modelData.name)
                  }
                }
              }


            }
          }

        }

        // -------------------------------------------------------------------
        // SCREEN 5: ADD / EDIT ITEM FORM
        // -------------------------------------------------------------------
        Column {
          visible: root.vault.status === "unlocked" && root.vault.activeScreen === "edit"
          width: parent.width
          spacing: Style.space(10)

          RowLayout {
            width: parent.width
            spacing: Style.space(8)

            Button {
              text: "Cancel (Esc)"
              iconText: "󰁍"
              fontFamily: root.fontFamily
              fontSize: Style.font.bodySmall
              onClicked: root.vault.currentScreen = root.vault.formIsEditing ? "detail" : "main"
            }

            Item { Layout.fillWidth: true }

            Text {
              textFormat: Text.PlainText
              Layout.alignment: Qt.AlignVCenter
              text: root.vault.formIsEditing ? "Edit Item" : "New Vault Item"
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

            WheelScroll { view: editFlickable }

            Column {
              id: editFormCol
              width: editFlickable.width - root.scrollGutter
              spacing: Style.space(10)

              // Item Type Selector (only for new items)
              Row {
                visible: !root.vault.formIsEditing
                spacing: Style.space(8)

                Button {
                  text: "Login"
                  iconText: "󰌋"
                  selected: root.vault.formTypeCode === 1
                  fontFamily: root.fontFamily
                  fontSize: Style.font.caption
                  onClicked: root.vault.changeFormType(1)
                }

                Button {
                  text: "Secure Note"
                  iconText: "󰈙"
                  selected: root.vault.formTypeCode === 2
                  fontFamily: root.fontFamily
                  fontSize: Style.font.caption
                  onClicked: root.vault.changeFormType(2)
                }
                Button {
                  text: "Card"
                  iconText: "󰿯"
                  selected: root.vault.formTypeCode === 3
                  fontFamily: root.fontFamily
                  fontSize: Style.font.caption
                  onClicked: root.vault.changeFormType(3)
                }

                Button {
                  text: "Identity"
                  iconText: ""
                  selected: root.vault.formTypeCode === 4
                  fontFamily: root.fontFamily
                  fontSize: Style.font.caption
                  onClicked: root.vault.changeFormType(4)
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
                  text: root.vault.formName
                  onTextChanged: root.vault.formName = text
                }
              }

              // FIELD: Folder -- an expandable list.
              Column {
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "FOLDER"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }

                Button {
                  width: parent.width
                  text: Model.plainLabel(root.vault.formFolderLabel())
                  iconText: root.vault.formPicker === "folder" ? "\u{F0140}" : "\u{F024B}"
                  selected: root.vault.formPicker === "folder"
                  accent: Color.accent
                  fontFamily: root.fontFamily
                  fontSize: Style.font.bodySmall
                  leftAlign: true
                  onClicked: root.vault.toggleFormPicker("folder")
                }

                Flickable {
                  id: folderPickList
                  visible: root.vault.formPicker === "folder"
                  width: parent.width
                  height: visible ? Math.min(Style.space(150), folderPickCol.implicitHeight) : 0
                  contentWidth: width
                  contentHeight: folderPickCol.implicitHeight
                  clip: true
                  boundsBehavior: Flickable.StopAtBounds
                  flickableDirection: Flickable.VerticalFlick
                  ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

                  WheelScroll { view: folderPickList }

                  Column {
                    id: folderPickCol
                    width: folderPickList.width - root.scrollGutter
                    spacing: Style.space(2)

                    FormPickerRow {
                      width: parent.width
                      foreground: root.fg
                      fontFamily: root.fontFamily
                      label: "No Folder"
                      glyph: "\u{F0256}"
                      picked: !root.vault.formFolderId
                      onActivated: root.vault.setFormFolder("")
                    }

                    Repeater {
                      model: root.vault.folders
                      delegate: FormPickerRow {
                        required property var modelData
                        width: parent.width
                        foreground: root.fg
                        fontFamily: root.fontFamily
                        label: modelData.name
                        glyph: "\u{F024B}"
                        picked: root.vault.formFolderId === modelData.id
                        onActivated: root.vault.setFormFolder(modelData.id)
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
                    text: root.vault.newFolderName
                    onTextChanged: root.vault.newFolderName = text
                    onAccepted: root.vault.submitNewFolder()
                    enabled: !root.vault.creatingFolder
                  }

                  Button {
                    text: root.vault.creatingFolder ? "Adding..." : "Add"
                    iconText: root.vault.creatingFolder ? "\u{F0450}" : "\u{F0415}"
                    iconSpinning: root.vault.creatingFolder
                    fontFamily: root.fontFamily
                    fontSize: Style.font.caption
                    enabled: !root.vault.creatingFolder && root.vault.newFolderName.trim() !== ""
                    onClicked: root.vault.submitNewFolder()
                  }
                }
              }

              // FIELD: Organization, and the collections it files items into.
              Column {
                visible: root.vault.organizations.length > 0
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "ORGANIZATION"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }

                Button {
                  width: parent.width
                  text: Model.plainLabel(root.vault.formOrgLabel())
                  iconText: root.vault.formPicker === "organization" ? "\u{F0140}" : "\u{F0991}"
                  selected: root.vault.formPicker === "organization"
                  accent: Color.accent
                  fontFamily: root.fontFamily
                  fontSize: Style.font.bodySmall
                  leftAlign: true
                  onClicked: root.vault.toggleFormPicker("organization")
                }

                Flickable {
                  id: orgPickList
                  visible: root.vault.formPicker === "organization"
                  width: parent.width
                  height: visible ? Math.min(Style.space(150), orgPickCol.implicitHeight) : 0
                  contentWidth: width
                  contentHeight: orgPickCol.implicitHeight
                  clip: true
                  boundsBehavior: Flickable.StopAtBounds
                  flickableDirection: Flickable.VerticalFlick
                  ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

                  WheelScroll { view: orgPickList }

                  Column {
                    id: orgPickCol
                    width: orgPickList.width - root.scrollGutter
                    spacing: Style.space(2)

                    FormPickerRow {
                      width: parent.width
                      foreground: root.fg
                      fontFamily: root.fontFamily
                      label: "My Vault"
                      glyph: "\u{F0004}"
                      picked: !root.vault.formOrgId || root.vault.formOrgId === "personal"
                      onActivated: root.vault.setFormOrganization("")
                    }

                    Repeater {
                      model: root.vault.organizations
                      delegate: FormPickerRow {
                        required property var modelData
                        width: parent.width
                        foreground: root.fg
                        fontFamily: root.fontFamily
                        label: modelData.name
                        glyph: "\u{F0991}"
                        picked: root.vault.formOrgId === modelData.id
                        onActivated: root.vault.setFormOrganization(modelData.id)
                      }
                    }
                  }
                }

                // Only for org-owned items, which need at least one.
                Column {
                  visible: Boolean(root.vault.formOrgId) && root.vault.formOrgId !== "personal"
                  width: parent.width
                  spacing: Style.space(3)

                  Item { width: 1; height: Style.space(4) }

                  Row {
                    width: parent.width
                    spacing: Style.space(6)
                    Text {
                      textFormat: Text.PlainText
                      text: "COLLECTIONS"
                      color: root.vault.formCollectionIds.length === 0 ? root.urgent : root.dim
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.caption
                      font.bold: true
                    }
                    Text {
                      textFormat: Text.PlainText
                      text: root.vault.formCollectionsLoading
                        ? "loading..."
                        : (root.vault.formCollectionIds.length === 0
                            ? "pick at least one"
                            : root.vault.formCollectionIds.length + " selected")
                      color: root.vault.formCollectionIds.length === 0 ? root.urgent : root.dim
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

                    WheelScroll { view: collectionList }

                    Column {
                      id: collectionCol
                      width: collectionList.width - root.scrollGutter
                      spacing: Style.space(2)

                      Text {
                        textFormat: Text.PlainText
                        visible: !root.vault.formCollectionsLoading && root.vault.formCollections.length === 0
                        width: parent.width
                        text: "No collections available in this organization."
                        color: root.dim
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.caption
                        wrapMode: Text.WordWrap
                      }

                      Repeater {
                        model: root.vault.formCollections
                        delegate: FormPickerRow {
                          required property var modelData
                          width: parent.width
                          foreground: root.fg
                          fontFamily: root.fontFamily
                          label: modelData.name
                          glyph: "\u{F0290}"
                          picked: root.vault.isFormCollectionSelected(modelData.id)
                          // An item can be in several collections.
                          multi: true
                          onActivated: root.vault.toggleFormCollection(modelData.id)
                        }
                      }
                    }
                  }
                }
              }

              // FIELD: Username (Login only)
              Column {
                visible: root.vault.formTypeCode === 1
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "USERNAME / EMAIL"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: "username or email address..."
                  text: root.vault.formUsername
                  onTextChanged: root.vault.formUsername = text
                }
              }

              // FIELD: Password with Generator (Login only)
              Column {
                visible: root.vault.formTypeCode === 1
                width: parent.width
                spacing: Style.space(3)
                RowLayout {
                  width: parent.width
                  Text { textFormat: Text.PlainText; text: "PASSWORD"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                  Item { Layout.fillWidth: true }
                  // Opens the generator, which fills this field and returns.
                  Button {
                    text: "Generate..."
                    iconText: "󰌆"
                    fontFamily: root.fontFamily
                    fontSize: Style.font.caption
                    onClicked: root.vault.openGenerator()
                  }
                }
                Row {
                  width: parent.width
                  spacing: Style.space(6)
                  TextField {
                    id: formPassField
                    width: parent.width - eyeBtnForm.width - Style.space(6)
                    placeholderText: "Password..."
                    password: !root.vault.formPasswordRevealed
                    text: root.vault.formPassword
                    onTextChanged: root.vault.formPassword = text
                  }
                  Button {
                    id: eyeBtnForm
                    iconText: root.vault.formPasswordRevealed ? "󰈉" : "󰈈"
                    tooltipText: root.vault.formPasswordRevealed ? "Hide password" : "Show password"
                    fontFamily: root.fontFamily
                    onClicked: root.vault.formPasswordRevealed = !root.vault.formPasswordRevealed
                  }
                }
              }

              // FIELD: TOTP Authenticator Key (Login only)
              Column {
                visible: root.vault.formTypeCode === 1
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "AUTHENTICATOR KEY (TOTP SECRET)"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: "e.g. JBSWY3DPEHPK3PXP (optional)..."
                  text: root.vault.formTotp
                  onTextChanged: root.vault.formTotp = text
                }
              }

              // FIELD: Website URL (Login only)
              Column {
                visible: root.vault.formTypeCode === 1
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "WEBSITE URL"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: "https://example.com/login..."
                  text: root.vault.formUri
                  onTextChanged: root.vault.formUri = text
                }
              }

              // -----------------------------------------------------------
              // FORM FIELDS: Card
              // -----------------------------------------------------------
              // Expiry as two boxes here: the vault stores two values.
              Column {
                visible: root.vault.formTypeCode === 3
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "CARDHOLDER NAME"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: "Name as printed on the card"
                  text: root.vault.formCardholderName
                  onTextChanged: root.vault.formCardholderName = text
                }
              }
              Column {
                visible: root.vault.formTypeCode === 3
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "BRAND"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: "Visa, Mastercard, Amex..."
                  text: root.vault.formCardBrand
                  onTextChanged: root.vault.formCardBrand = text
                }
              }
              Column {
                visible: root.vault.formTypeCode === 3
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "CARD NUMBER"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: "1234 5678 9012 3456"
                  text: root.vault.formCardNumber
                  onTextChanged: root.vault.formCardNumber = text
                }
              }
              Column {
                visible: root.vault.formTypeCode === 3
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "EXPIRY MONTH"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: "MM"
                  text: root.vault.formCardExpMonth
                  onTextChanged: root.vault.formCardExpMonth = text
                }
              }
              Column {
                visible: root.vault.formTypeCode === 3
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "EXPIRY YEAR"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: "YYYY"
                  text: root.vault.formCardExpYear
                  onTextChanged: root.vault.formCardExpYear = text
                }
              }
              Column {
                visible: root.vault.formTypeCode === 3
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "SECURITY CODE"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: "CVV / CVC"
                  text: root.vault.formCardCode
                  onTextChanged: root.vault.formCardCode = text
                }
              }

              // -----------------------------------------------------------
              // FORM FIELDS: Identity
              // -----------------------------------------------------------
              Column {
                visible: root.vault.formTypeCode === 4
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "TITLE"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: "Mr, Ms, Dr..."
                  text: root.vault.formIdTitle
                  onTextChanged: root.vault.formIdTitle = text
                }
              }
              Column {
                visible: root.vault.formTypeCode === 4
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "FIRST NAME"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: ""
                  text: root.vault.formIdFirstName
                  onTextChanged: root.vault.formIdFirstName = text
                }
              }
              Column {
                visible: root.vault.formTypeCode === 4
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "MIDDLE NAME"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: ""
                  text: root.vault.formIdMiddleName
                  onTextChanged: root.vault.formIdMiddleName = text
                }
              }
              Column {
                visible: root.vault.formTypeCode === 4
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "LAST NAME"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: ""
                  text: root.vault.formIdLastName
                  onTextChanged: root.vault.formIdLastName = text
                }
              }
              Column {
                visible: root.vault.formTypeCode === 4
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "USERNAME"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: ""
                  text: root.vault.formIdUsername
                  onTextChanged: root.vault.formIdUsername = text
                }
              }
              Column {
                visible: root.vault.formTypeCode === 4
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "COMPANY"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: ""
                  text: root.vault.formIdCompany
                  onTextChanged: root.vault.formIdCompany = text
                }
              }
              Column {
                visible: root.vault.formTypeCode === 4
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "EMAIL"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: "name@example.com"
                  text: root.vault.formIdEmail
                  onTextChanged: root.vault.formIdEmail = text
                }
              }
              Column {
                visible: root.vault.formTypeCode === 4
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "PHONE"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: ""
                  text: root.vault.formIdPhone
                  onTextChanged: root.vault.formIdPhone = text
                }
              }
              Column {
                visible: root.vault.formTypeCode === 4
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "SOCIAL SECURITY NUMBER"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: ""
                  text: root.vault.formIdSsn
                  onTextChanged: root.vault.formIdSsn = text
                }
              }
              Column {
                visible: root.vault.formTypeCode === 4
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "PASSPORT NUMBER"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: ""
                  text: root.vault.formIdPassport
                  onTextChanged: root.vault.formIdPassport = text
                }
              }
              Column {
                visible: root.vault.formTypeCode === 4
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "LICENCE NUMBER"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: ""
                  text: root.vault.formIdLicense
                  onTextChanged: root.vault.formIdLicense = text
                }
              }
              Column {
                visible: root.vault.formTypeCode === 4
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "ADDRESS LINE 1"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: ""
                  text: root.vault.formIdAddress1
                  onTextChanged: root.vault.formIdAddress1 = text
                }
              }
              Column {
                visible: root.vault.formTypeCode === 4
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "ADDRESS LINE 2"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: ""
                  text: root.vault.formIdAddress2
                  onTextChanged: root.vault.formIdAddress2 = text
                }
              }
              Column {
                visible: root.vault.formTypeCode === 4
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "ADDRESS LINE 3"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: ""
                  text: root.vault.formIdAddress3
                  onTextChanged: root.vault.formIdAddress3 = text
                }
              }
              Column {
                visible: root.vault.formTypeCode === 4
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "CITY / TOWN"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: ""
                  text: root.vault.formIdCity
                  onTextChanged: root.vault.formIdCity = text
                }
              }
              Column {
                visible: root.vault.formTypeCode === 4
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "STATE / COUNTY"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: ""
                  text: root.vault.formIdState
                  onTextChanged: root.vault.formIdState = text
                }
              }
              Column {
                visible: root.vault.formTypeCode === 4
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "POSTAL CODE"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: ""
                  text: root.vault.formIdPostalCode
                  onTextChanged: root.vault.formIdPostalCode = text
                }
              }
              Column {
                visible: root.vault.formTypeCode === 4
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "COUNTRY"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: ""
                  text: root.vault.formIdCountry
                  onTextChanged: root.vault.formIdCountry = text
                }
              }

              CustomFieldsEditor {
                vault: root.vault
                width: parent.width
                panel: root
              }

              // FIELD: Notes
              Column {
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "NOTES"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: "Additional secure notes..."
                  text: root.vault.formNotes
                  onTextChanged: root.vault.formNotes = text
                }
              }

              // Favorite Star Toggle
              Row {
                spacing: Style.space(8)
                Button {
                  text: root.vault.formFavorite ? "★ In Favorites" : "☆ Add to Favorites"
                  selected: root.vault.formFavorite
                  accent: Color.accent
                  fontFamily: root.fontFamily
                  fontSize: Style.font.bodySmall
                  onClicked: root.vault.formFavorite = !root.vault.formFavorite
                }
              }

              // Enter saves from anywhere in the form (one Shortcut rather than
              // onAccepted on 30+ fields), except while a picker has it.
              Shortcut {
                sequences: ["Return", "Enter"]
                enabled: root.vault.activeScreen === "edit" && root.vault.formPicker === ""
                onActivated: root.vault.saveItemForm()
              }

              // Save Action Button
              Button {
                width: parent.width
                text: root.vault.isLoading
                  ? "Saving..."
                  : (root.vault.formIsEditing ? "Save Changes (Enter)" : "Create Item (Enter)")
                iconText: root.vault.isLoading ? "󰑐" : "󰄬"
                iconSpinning: root.vault.isLoading
                selected: true
                accent: Color.accent
                fontFamily: root.fontFamily
                enabled: !root.vault.isLoading && root.vault.formPicker === ""
                onClicked: root.vault.saveItemForm()
              }

              Item { height: Style.space(12); width: 1 }
            }
          }
        }
      }

      // Overlaid beside mainColumn, outside the layout, so messages never
      // shift the active screen.
      StatusNotice {
        id: statusNotice
        statusMessage: root.vault.flashMessage
        errorMessage: root.vault.errorMessage
        statusSuppressed: root.vault.totpFollowupActive
        foreground: root.fg
        surfaceColor: root.bar ? root.bar.background : Color.background
        accentColor: root.accent
        urgentColor: root.urgent
        fontFamily: root.fontFamily
        actionLabel: root.vault.failedSave
          ? Model.plainLabel("Reopen " + Model.clipLabel(root.vault.failedSave.name, 24))
          : ""
        onActionRequested: root.vault.reopenFailedSave()
        onErrorDismissed: {
          // Dismissing also drops the Reopen recovery.
          root.vault.failedSave = null
          root.vault.errorMessage = ""
        }
      }
    }
  }
}
