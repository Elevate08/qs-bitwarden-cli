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

  width: parent ? parent.width : 0
  spacing: Style.space(14)

  // `visible` is effective visibility, so this also runs when SCREEN 2 or the
  // SSH unlock screen hides the form (tests/qml/tst_visibility.qml).
  onVisibleChanged: if (!visible) resetReveal()

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
      text: form.vault.fingerprintScanning ? "󰈷" : "󰌋"
      color: form.vault.fingerprintScanning ? Color.accent : form.panel.fg
      opacity: 0.85
      font.family: form.panel.fontFamily
      font.pixelSize: Style.space(38)

      SequentialAnimation on opacity {
        running: form.vault.fingerprintScanning
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
        : (form.vault.fingerprintReady ? "Unlock Vault" : "Enter Master Password")
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

  Text {
    textFormat: Text.PlainText
    visible: form.vault.fingerprintMessage !== ""
    width: parent.width
    horizontalAlignment: Text.AlignHCenter
    text: form.vault.fingerprintMessage
    color: form.vault.fingerprintScanning ? Color.accent : form.panel.dim
    font.family: form.panel.fontFamily
    font.pixelSize: Style.font.bodySmall
    wrapMode: Text.WordWrap
  }

  Text {
    textFormat: Text.PlainText
    visible: form.vault.fingerprintUnlock && form.vault.fingerprintAvailable && !form.vault.fingerprintStored
    width: parent.width
    horizontalAlignment: Text.AlignHCenter
    text: "󰈷  Unlock once with your master password to enable fingerprint unlock."
    color: form.panel.dim
    font.family: form.panel.fontFamily
    font.pixelSize: Style.font.caption
    wrapMode: Text.WordWrap
  }

  Column {
    visible: form.fieldsOffered && form.vault.pinReady
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

    Row {
      width: parent.width
      spacing: Style.space(8)

      TextField {
        id: pinField
        width: parent.width - pinUnlockBtn.width - Style.space(8)
        placeholderText: "Enter your PIN..."
        password: true
        text: form.vault.pinEntry
        onTextChanged: form.vault.pinEntry = text.replace(/[^0-9]/g, "")
        onAccepted: form.vault.submitPinUnlock()
        enabled: !form.vault.pinBusy && !form.vault.isUnlocking
      }

      Button {
        id: pinUnlockBtn
        text: form.vault.pinBusy ? "Checking..." : "Unlock"
        iconText: form.vault.pinBusy ? "󰑐" : "󰌿"
        iconSpinning: form.vault.pinBusy
        selected: true
        accent: Color.accent
        fontFamily: form.panel.fontFamily
        focusable: form.buttonsFocusable
        enabled: !form.vault.pinBusy && !form.vault.isUnlocking
        onClicked: form.vault.submitPinUnlock()
      }
    }

    Text {
      textFormat: Text.PlainText
      visible: form.vault.pinError !== ""
      width: parent.width
      text: form.vault.pinError
      color: form.panel.urgent
      font.family: form.panel.fontFamily
      font.pixelSize: Style.font.bodySmall
      wrapMode: Text.WordWrap
    }

    Text {
      textFormat: Text.PlainText
      text: "or use your master password below"
      color: form.panel.dim
      font.family: form.panel.fontFamily
      font.pixelSize: Style.font.caption
    }
  }

  // A PIN was set but the vault rejected it -- surfaced even once pinReady
  // has gone false, so the reason is not lost on the popup path either.
  Text {
    textFormat: Text.PlainText
    visible: form.fieldsOffered && !form.vault.pinReady && form.vault.pinError !== ""
    width: parent.width
    horizontalAlignment: Text.AlignHCenter
    text: form.vault.pinError
    color: form.panel.urgent
    font.family: form.panel.fontFamily
    font.pixelSize: Style.font.bodySmall
    wrapMode: Text.WordWrap
  }

  Column {
    visible: form.fieldsOffered
    width: parent.width
    spacing: Style.space(10)

    Button {
      visible: form.vault.fingerprintReady
      width: parent.width
      text: form.vault.fingerprintScanning ? "Waiting for fingerprint..." : "Unlock with Fingerprint"
      iconText: "󰈷"
      selected: true
      accent: Color.accent
      fontFamily: form.panel.fontFamily
      focusable: form.buttonsFocusable
      enabled: !form.vault.isUnlocking && !form.vault.fingerprintScanning
      onClicked: form.vault.startFingerprintUnlock()
    }

    Row {
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

    Button {
      width: parent.width
      text: form.vault.isUnlocking ? "Unlocking..." : "Unlock Vault"
      iconText: form.vault.isUnlocking ? "󰑐" : "󰌋"
      iconSpinning: form.vault.isUnlocking
      selected: true
      accent: Color.accent
      fontFamily: form.panel.fontFamily
      focusable: form.buttonsFocusable
      enabled: !form.vault.isUnlocking
      onClicked: form.vault.unlockVault()
    }
  }
}
