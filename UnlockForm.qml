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
  // password. `chosen` (set by "use X instead") is ignored once that method
  // becomes unavailable, e.g. an exhausted PIN or a closed lid.
  property string chosen: ""
  readonly property string method: chosen !== "" && methodAvailable(chosen)
    ? chosen
    : (methodAvailable("fido") ? "fido"
      : (methodAvailable("fingerprint") ? "fingerprint"
        : (methodAvailable("pin") ? "pin" : "password")))
  readonly property string nextMethod: nextMethodAfter(method)
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

  function nextMethodAfter(name) {
    var order = ["fido", "fingerprint", "pin", "password"]
    var from = order.indexOf(name)
    for (var step = 1; step < order.length; step++) {
      var candidate = order[(from + step) % order.length]
      if (methodAvailable(candidate)) return candidate
    }
    return ""
  }

  function methodLabel(name) {
    if (name === "fido") return "your FIDO2 key"
    if (name === "fingerprint") return "fingerprint"
    if (name === "pin") return "PIN"
    return "master password"
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
        : ((form.vault.fidoReady || form.vault.fingerprintReady)
          ? "Unlock Vault"
          : "Enter Master Password")
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
    text: form.busy ? (form.method === "pin" ? "Checking..." : "Unlocking...") : "Unlock Vault"
    iconText: form.busy ? "󰑐" : "󰌋"
    iconSpinning: form.busy
    selected: true
    accent: Color.accent
    fontFamily: form.panel.fontFamily
    focusable: form.buttonsFocusable
    enabled: !form.busy
    onClicked: form.submitCurrentMethod()
  }

  // Cycles to the next available method.
  Button {
    visible: form.fieldsOffered && form.nextMethod !== ""
    width: parent.width
    text: "Use " + form.methodLabel(form.nextMethod) + " instead"
    iconText: form.nextMethod === "fido"
      ? "󰟵"
      : (form.nextMethod === "fingerprint" ? "󰈷" : (form.nextMethod === "pin" ? "󰌿" : "󰌋"))
    fontFamily: form.panel.fontFamily
    fontSize: Style.font.bodySmall
    focusable: form.buttonsFocusable
    onClicked: form.useMethod(form.nextMethod)
  }
}
