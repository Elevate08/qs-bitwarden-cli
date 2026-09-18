import QtQuick
import qs.Commons
import qs.Ui

// The lock-screen unlock controls: fingerprint, PIN, and master password.
// Shared by Panel SCREEN 2 and the SSH unlock popup so those copies cannot
// drift (stale-PIN error, eye-reveal reset).
Column {
  id: form

  required property var panel
  required property var vault

  readonly property alias passwordField: passwordField
  readonly property alias pinField: pinField
  // The popup opts in so Tab can reach Deny/Unlock. The panel lock screen
  // leaves these false so KeyboardPanel stays on the PIN/password field.
  property bool buttonsFocusable: false
  // Whether the PIN and password controls are drawn. SCREEN 2 is shown while
  // status is still "checking" and keeps its fields there; hidden once the
  // vault is unlocked, so the SSH load title can take over. The SSH popup
  // narrows this to "locked": a submit before status is known cannot succeed.
  property bool fieldsOffered: form.vault.status === "locked" || form.vault.status === "checking"
  // Drawn between the header and the unlock controls. The SSH popup puts its
  // request context here so the title stays on top; the panel passes nothing.
  property alias context: contextSlot.data

  // One method at a time. A plugged-in FIDO2 key leads -- it is the one the
  // user chose to have in their hand -- then the fingerprint reader, then a
  // configured PIN, then the master password, which is always there and so is
  // the last stop. `chosen` is what the "use X instead" button set; it is
  // ignored the moment that method stops being available, which is how an
  // exhausted PIN (the vault clears it after too many attempts) or a closed
  // lid hands over without anything having to watch for the failure.
  property string chosen: ""
  readonly property string method: chosen !== "" && methodAvailable(chosen)
    ? chosen
    : (methodAvailable("fido") ? "fido"
      : (methodAvailable("fingerprint") ? "fingerprint"
        : (methodAvailable("pin") ? "pin" : "password")))
  readonly property string nextMethod: nextMethodAfter(method)
  // The field this method types into, for the panel's focus target and the
  // popup's focusDefault(). Fingerprint has none.
  readonly property var focusField: method === "pin"
    ? pinField
    : (method === "password" ? passwordField : null)
  // A FIDO2 attempt, on the same three phases as the fingerprint's.
  readonly property bool fidoBusy: form.vault.fidoScanning
    || form.vault.fidoAuthorized
    || (form.vault.isUnlocking && form.vault.pendingUnlockFrom === "fido")
  // A fingerprint attempt, from the touch prompt to the unlock it starts:
  // scanning, then authorized while the keyring is read, then the unlock the
  // stored password drives.
  readonly property bool fingerprintBusy: form.vault.fingerprintScanning
    || form.vault.fingerprintAuthorized
    || (form.vault.isUnlocking && form.vault.pendingUnlockFrom === "fingerprint")
  readonly property bool busy: method === "pin"
    ? (form.vault.pinBusy || form.vault.isUnlocking)
    : form.vault.isUnlocking

  width: parent ? parent.width : 0
  spacing: Style.space(14)

  // `visible` is effective visibility, so this also runs when SCREEN 2 or the
  // SSH unlock screen hides the form (tests/qml/tst_visibility.qml). A method
  // picked by hand lasts as long as the screen that offered it.
  onVisibleChanged: {
    if (!visible) {
      resetReveal()
      form.chosen = ""
      return
    }
    armOfferedMethod()
  }

  // A method that stops being offered -- a key unplugged, a lid shut, a PIN
  // spent -- must not leave its reader or key waiting behind the screen that
  // replaced it.
  onMethodChanged: {
    if (method !== "fido") form.vault.releaseFidoUnlock()
    if (method !== "fingerprint") form.vault.cancelFingerprintUnlock()
    armOfferedMethod()
  }

  // The offered method is the armed one. Every path that puts this form on
  // screen goes through here, so none of them has to remember to arm anything
  // -- and a presence method is never offered without something waiting behind
  // it, which is what leaves a key blinking or a touch going to a text field.
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
      // Accent whichever glyph is showing: the key over the PIN and password
      // screens reads as part of the same prompt as the fingerprint does.
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

  // Only on the FIDO2 screen, for the reason the fingerprint prompt is scoped
  // to its own: no other screen has a key to touch.
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

  // Only on the fingerprint screen: a PIN or password screen has no reader to
  // touch, and the prompt outlives the scan the lock screen starts by itself.
  Text {
    textFormat: Text.PlainText
    visible: form.method === "fingerprint" && form.vault.fingerprintMessage !== ""
    width: parent.width
    horizontalAlignment: Text.AlignHCenter
    text: form.vault.fingerprintMessage
    // Accent for the whole fingerprint attempt, not only the scan: the verified
    // line is the same thought as the touch prompt and should not fade into an
    // ordinary note halfway through.
    color: form.fingerprintBusy ? Color.accent : form.panel.dim
    font.family: form.panel.fontFamily
    font.pixelSize: Style.font.bodySmall
    wrapMode: Text.WordWrap
  }

  // Why the last FIDO2 attempt failed, on every screen, for the same reason a
  // failed fingerprint travels: an unreadable key is when the user moves on.
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

  // Why the last fingerprint attempt failed, on every screen: an unreadable
  // finger is exactly when the user moves to the PIN or password, and the
  // reason has to come with them.
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

  // Offered on the master-password screen, which is the one that can enrol.
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

  // A PIN the vault rejected, kept on screen after the PIN method has gone --
  // an exhausted PIN clears itself, and the reason must survive that.
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

  // Fingerprint asks for a finger and nothing else: no field, and no Unlock
  // button to press afterwards.
  Button {
    visible: form.fieldsOffered && form.method === "fingerprint"
    width: parent.width
    // A read finger ends the scan and starts the unlock, and the button went
    // back to inviting a touch that was already given. It says what the vault
    // is doing instead, the same way the typed methods do.
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

  // One Unlock Vault button for both typed methods, so the PIN and the master
  // password are submitted the same way.
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

  // The way back to anything else that is set up. One button rather than a
  // list: with two methods it is a toggle, with three it cycles.
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
