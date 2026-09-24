import QtQuick
import qs.Commons
import qs.Ui

// The lock-screen unlock controls (FIDO2, fingerprint, PIN, master password),
// shared by the panel lock screen and the SSH unlock popup.
Column {
  id: form

  required property var panel
  required property var vault

  readonly property alias passwordField: passwordField
  readonly property alias pinField: pinField
  // The popup lets Tab reach the buttons; the panel keeps focus on the field.
  property bool buttonsFocusable: false
  // Whether the PIN/password controls are drawn: while locked or checking by
  // default; the SSH popup narrows it to "locked".
  property bool fieldsOffered: form.vault.status === "locked" || form.vault.status === "checking"
  // Drawn between the header and the controls (the SSH popup's request context).
  property alias context: contextSlot.data

  // One method at a time, first available of FIDO2, fingerprint, PIN, master
  // password. `chosen` (set by picking another method in the row) is ignored
  // once that method becomes unavailable, e.g. an exhausted PIN or a closed
  // lid.
  property string chosen: ""
  readonly property string method: chosen !== "" && methodAvailable(chosen)
    ? chosen
    : (methodAvailable("fido") ? "fido"
      : (methodAvailable("fingerprint") ? "fingerprint"
        : (methodAvailable("pin") ? "pin" : "password")))
  // Every method set up and usable right now, in the order above; the row
  // offers each one, and a method turned off in settings is not in it.
  readonly property var availableMethods: ["fido", "fingerprint", "pin", "password"]
    .filter(function(name) { return methodAvailable(name) })
  // The field this method types into (none for fingerprint or FIDO2).
  readonly property var focusField: method === "pin"
    ? pinField
    : (method === "password" ? passwordField : null)
  // A FIDO2 attempt: scanning, authorized, then unlocking.
  readonly property bool fidoBusy: form.vault.fidoScanning
    || form.vault.fidoAuthorized
    || (form.vault.isUnlocking && form.vault.pendingUnlockFrom === "fido")
  // A fingerprint attempt: scanning, authorized, then unlocking.
  readonly property bool fingerprintBusy: form.vault.fingerprintScanning
    || form.vault.fingerprintAuthorized
    || (form.vault.isUnlocking && form.vault.pendingUnlockFrom === "fingerprint")
  // Submitting needs a known locked vault; typing does not.
  readonly property bool canSubmit: form.vault.status === "locked"
  readonly property bool busy: method === "pin"
    ? (form.vault.pinBusy || form.vault.isUnlocking)
    : form.vault.isUnlocking

  width: parent ? parent.width : 0
  spacing: Style.space(14)

  // Effective visibility, so this also runs when a parent hides the form. A
  // hand-picked method lasts as long as the screen that offered it.
  onVisibleChanged: {
    if (!visible) {
      resetReveal()
      form.chosen = ""
      return
    }
    armOfferedMethod()
  }

  // A method no longer offered must not leave its reader or key waiting.
  onMethodChanged: {
    if (method !== "fido") form.vault.releaseFidoUnlock()
    if (method !== "fingerprint") form.vault.cancelFingerprintUnlock()
    armOfferedMethod()
  }

  // Arms the offered presence method; every path that shows the form comes
  // through here.
  function armOfferedMethod() {
    if (!visible || !fieldsOffered || form.vault.status !== "locked") return
    if (form.vault.isUnlocking) return
    if (method === "fido") form.vault.startFidoUnlock()
    else if (method === "fingerprint") form.vault.startFingerprintUnlock()
  }

  onFieldsOfferedChanged: armOfferedMethod()

  function methodAvailable(name) {
    if (name === "fido") return form.vault.fidoReady
    if (name === "fingerprint") return form.vault.fingerprintReady
    if (name === "pin") return form.vault.pinReady
    return name === "password"
  }

  function methodLabel(name) {
    if (name === "fido") return "FIDO2 Key"
    if (name === "fingerprint") return "Fingerprint"
    if (name === "pin") return "PIN"
    return "Password"
  }

  function methodIcon(name) {
    if (name === "fido") return "󰟵"
    if (name === "fingerprint") return "󰈷"
    if (name === "pin") return "󰌿"
    return "󰌋"
  }

  function useMethod(name) {
    if (name === "" || !methodAvailable(name)) return
    form.chosen = name
    form.vault.cancelFingerprintUnlock()
    form.vault.releaseFidoUnlock()
    if (name === "fingerprint") {
      form.vault.startFingerprintUnlock()
      return
    }
    if (name === "fido") {
      form.vault.startFidoUnlock()
      return
    }
    if (form.focusField) form.focusField.forceActiveFocus()
  }

  function submitCurrentMethod() {
    if (form.method === "pin") form.vault.submitPinUnlock()
    else form.vault.unlockVault()
  }

  // Re-point, never copy: see syncLoginFields() in Panel.qml.
  function syncFromVault() {
    pinField.text = Qt.binding(function() { return form.vault.pinEntry })
    passwordField.text = Qt.binding(function() { return form.vault.masterPassword })
    if (!form.vault.masterPassword) resetReveal()
  }

  function resetReveal() {
    eyeBtnUnlock.revealed = false
  }

  Column {
    anchors.horizontalCenter: parent.horizontalCenter
    spacing: Style.space(6)

    Text {
      id: fingerprintIcon
      textFormat: Text.PlainText
      anchors.horizontalCenter: parent.horizontalCenter
      text: form.method === "fido" ? "󰟵" : (form.fingerprintBusy ? "󰈷" : "󰌋")
      // Accent the key glyph on the PIN and password screens too.
      color: Color.accent
      opacity: 0.85
      font.family: form.panel.fontFamily
      font.pixelSize: Style.space(38)

      SequentialAnimation on opacity {
        running: form.vault.fingerprintScanning || form.vault.fidoScanning
        loops: Animation.Infinite
        NumberAnimation { to: 0.35; duration: 700; easing.type: Easing.InOutQuad }
        NumberAnimation { to: 0.95; duration: 700; easing.type: Easing.InOutQuad }
        onStopped: fingerprintIcon.opacity = 0.85
      }
    }

    Text {
      textFormat: Text.PlainText
      anchors.horizontalCenter: parent.horizontalCenter
      text: form.vault.status === "unlocked"
        ? "Loading SSH keys"
        : (form.method === "password" ? "Enter Master Password"
          : (form.method === "pin" ? "Enter PIN" : "Unlock Vault"))
      color: form.panel.fg
      font.family: form.panel.fontFamily
      font.pixelSize: Style.font.title
      font.bold: true
    }

    Text {
      textFormat: Text.PlainText
      visible: form.vault.userEmail !== ""
      anchors.horizontalCenter: parent.horizontalCenter
      text: form.vault.userEmail
      color: form.panel.dim
      font.family: form.panel.fontFamily
      font.pixelSize: Style.font.bodySmall
    }
  }

  Column {
    id: contextSlot
    visible: children.length > 0
    width: parent.width
    spacing: Style.space(12)
  }

  // Only on the FIDO2 screen: no other has a key to touch.
  Text {
    textFormat: Text.PlainText
    visible: form.method === "fido" && form.vault.fidoMessage !== ""
    width: parent.width
    horizontalAlignment: Text.AlignHCenter
    text: form.vault.fidoMessage
    color: form.fidoBusy ? Color.accent : form.panel.dim
    font.family: form.panel.fontFamily
    font.pixelSize: Style.font.bodySmall
    wrapMode: Text.WordWrap
  }

  // Only on the fingerprint screen.
  Text {
    textFormat: Text.PlainText
    visible: form.method === "fingerprint" && form.vault.fingerprintMessage !== ""
    width: parent.width
    horizontalAlignment: Text.AlignHCenter
    text: form.vault.fingerprintMessage
    // Accented for the whole attempt, verification included.
    color: form.fingerprintBusy ? Color.accent : form.panel.dim
    font.family: form.panel.fontFamily
    font.pixelSize: Style.font.bodySmall
    wrapMode: Text.WordWrap
  }

  // Why the last FIDO2 attempt failed, on every screen, so it follows the user
  // to the next method.
  Text {
    textFormat: Text.PlainText
    visible: form.vault.fidoError !== ""
    width: parent.width
    horizontalAlignment: Text.AlignHCenter
    text: form.vault.fidoError
    color: form.panel.urgent
    font.family: form.panel.fontFamily
    font.pixelSize: Style.font.bodySmall
    wrapMode: Text.WordWrap
  }

  // Why the last fingerprint attempt failed, on every screen, likewise.
  Text {
    textFormat: Text.PlainText
    visible: form.vault.fingerprintError !== ""
    width: parent.width
    horizontalAlignment: Text.AlignHCenter
    text: form.vault.fingerprintError
    color: form.panel.urgent
    font.family: form.panel.fontFamily
    font.pixelSize: Style.font.bodySmall
    wrapMode: Text.WordWrap
  }

  // Offered on the master-password screen, which can enrol.
  Text {
    textFormat: Text.PlainText
    visible: form.method === "password" && form.vault.fingerprintUnlock
      && form.vault.fingerprintAvailable && !form.vault.fingerprintStored
    width: parent.width
    horizontalAlignment: Text.AlignHCenter
    text: "󰈷  Unlock once with your master password to enable fingerprint unlock."
    color: form.panel.dim
    font.family: form.panel.fontFamily
    font.pixelSize: Style.font.caption
    wrapMode: Text.WordWrap
  }

  // A rejected PIN stays shown after an exhausted PIN method disappears.
  Text {
    textFormat: Text.PlainText
    visible: form.fieldsOffered && form.method !== "pin" && form.vault.pinUnlockError !== ""
    width: parent.width
    horizontalAlignment: Text.AlignHCenter
    text: form.vault.pinUnlockError
    color: form.panel.urgent
    font.family: form.panel.fontFamily
    font.pixelSize: Style.font.bodySmall
    wrapMode: Text.WordWrap
  }

  // Fingerprint needs no field and no Unlock button.
  Button {
    visible: form.fieldsOffered && form.method === "fingerprint"
    width: parent.width
    // Once a finger is read, say what the vault is doing.
    text: form.vault.isUnlocking
      ? "Unlocking..."
      : (form.vault.fingerprintScanning ? "Waiting for fingerprint..." : "Unlock with Fingerprint")
    iconText: form.vault.isUnlocking ? "󰑐" : "󰈷"
    iconSpinning: form.vault.isUnlocking
    selected: true
    accent: Color.accent
    fontFamily: form.panel.fontFamily
    focusable: form.buttonsFocusable
    enabled: !form.vault.isUnlocking && !form.vault.fingerprintScanning
    onClicked: form.vault.startFingerprintUnlock()
  }

  Button {
    visible: form.fieldsOffered && form.method === "fido"
    width: parent.width
    text: (form.vault.fidoAuthorized || form.vault.isUnlocking)
      ? "Unlocking..."
      : (form.vault.fidoScanning ? "Waiting for your key..." : "Unlock with FIDO2 Key")
    iconText: (form.vault.fidoAuthorized || form.vault.isUnlocking) ? "󰑐" : "󰟵"
    iconSpinning: form.vault.fidoAuthorized || form.vault.isUnlocking
    selected: true
    accent: Color.accent
    fontFamily: form.panel.fontFamily
    focusable: form.buttonsFocusable
    enabled: !form.vault.isUnlocking && !form.vault.fidoScanning
    onClicked: form.vault.startFidoUnlock()
  }

  Column {
    visible: form.fieldsOffered && form.method === "pin"
    width: parent.width
    spacing: Style.space(8)

    Text {
      textFormat: Text.PlainText
      text: "PIN"
      color: form.panel.dim
      font.family: form.panel.fontFamily
      font.pixelSize: Style.font.caption
      font.bold: true
    }

    TextField {
      id: pinField
      width: parent.width
      placeholderText: "Enter your PIN..."
      password: true
      text: form.vault.pinEntry
      onTextChanged: form.vault.pinEntry = text.replace(/[^0-9]/g, "")
      onAccepted: form.vault.submitPinUnlock()
      enabled: !form.vault.pinBusy && !form.vault.isUnlocking
    }

    Text {
      textFormat: Text.PlainText
      visible: form.vault.pinUnlockError !== ""
      width: parent.width
      text: form.vault.pinUnlockError
      color: form.panel.urgent
      font.family: form.panel.fontFamily
      font.pixelSize: Style.font.bodySmall
      wrapMode: Text.WordWrap
    }
  }

  Row {
    visible: form.fieldsOffered && form.method === "password"
    width: parent.width
    spacing: Style.space(8)

    TextField {
      id: passwordField
      width: parent.width - eyeBtnUnlock.width - Style.space(8)
      placeholderText: "Master password..."
      password: !eyeBtnUnlock.revealed
      text: form.vault.masterPassword
      onTextChanged: form.vault.masterPassword = text
      onActiveFocusChanged: if (activeFocus) form.vault.prepareUnlock()
      onAccepted: form.vault.unlockVault()
      enabled: !form.vault.isUnlocking
    }

    Button {
      id: eyeBtnUnlock
      property bool revealed: false
      iconText: revealed ? "󰈉" : "󰈈"
      tooltipText: revealed ? "Hide password" : "Show password"
      fontFamily: form.panel.fontFamily
      focusable: form.buttonsFocusable
      onClicked: revealed = !revealed
    }
  }

  // One Unlock button for both typed methods.
  Button {
    visible: form.fieldsOffered && form.method !== "fingerprint" && form.method !== "fido"
    width: parent.width
    text: form.busy ? (form.method === "pin" ? "Checking..." : "Unlocking...")
      : (form.canSubmit ? "Unlock Vault" : "Checking vault status...")
    iconText: form.busy || !form.canSubmit ? "󰑐" : "󰌋"
    iconSpinning: form.busy || !form.canSubmit
    selected: true
    accent: Color.accent
    fontFamily: form.panel.fontFamily
    focusable: form.buttonsFocusable
    enabled: !form.busy && form.canSubmit
    onClicked: form.submitCurrentMethod()
  }

  // Every available method side by side, one column each; the current one
  // is selected. Only when there is a choice to make.
  Row {
    id: methodRow
    visible: form.fieldsOffered && form.availableMethods.length > 1
    width: parent.width
    spacing: Style.space(6)

    Repeater {
      model: form.availableMethods

      delegate: Button {
        id: methodTile
        required property string modelData
        width: (methodRow.width - methodRow.spacing * (form.availableMethods.length - 1))
          / Math.max(1, form.availableMethods.length)
        height: tileColumn.implicitHeight + Style.space(12)
        bordered: true
        selected: form.method === modelData
        accent: Color.accent
        fontFamily: form.panel.fontFamily
        tooltipText: "Unlock with " + (modelData === "password" ? "your master password"
          : (modelData === "fido" ? "your FIDO2 key" : form.methodLabel(modelData).toLowerCase()))
        focusable: form.buttonsFocusable
        onClicked: form.useMethod(modelData)

        Column {
          id: tileColumn
          anchors.centerIn: parent
          spacing: Style.space(2)

          Text {
            textFormat: Text.PlainText
            anchors.horizontalCenter: parent.horizontalCenter
            text: form.methodIcon(methodTile.modelData)
            color: methodTile.selected ? Style.selectedStateColor(methodTile.foreground, methodTile.accent) : methodTile.foreground
            font.family: form.panel.fontFamily
            font.pixelSize: Style.font.title
          }

          Text {
            textFormat: Text.PlainText
            anchors.horizontalCenter: parent.horizontalCenter
            text: form.methodLabel(methodTile.modelData)
            color: methodTile.selected ? Style.selectedStateColor(methodTile.foreground, methodTile.accent) : methodTile.foreground
            font.family: form.panel.fontFamily
            font.pixelSize: Style.font.caption
            font.bold: methodTile.selected
          }
        }
      }
    }
  }
}
