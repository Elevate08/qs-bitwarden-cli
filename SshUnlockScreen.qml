import QtQuick
import qs.Commons
import qs.Ui
import "BitwardenModel.js" as Model

// The first step of an SSH request when the vault is locked. Uses the same
// layout, pulsing fingerprint animation, and unlock controls as the panel's
// unlock screen, while keeping the SSH request context visible.
Column {
  id: screen

  required property var panel
  // The vault this panel shows (Service.qml); `panel` is the view that draws it.
  required property var vault
  property bool active: false

  visible: active && vault.sshUnlockRequest !== null
  width: parent ? parent.width : 0
  spacing: Style.space(12)

  onVisibleChanged: if (!visible && eyeBtnUnlock) eyeBtnUnlock.revealed = false
  onActiveChanged: if (!active && eyeBtnUnlock) eyeBtnUnlock.revealed = false

  component UnlockCaption: Text {
    textFormat: Text.PlainText
    width: parent ? parent.width : 0
    color: screen.panel.dim
    font.family: screen.panel.fontFamily
    font.pixelSize: Style.font.caption
    wrapMode: Text.WordWrap
  }

  function focusDefault() {
    if (!screen.active || !screen.visible) return
    screen.vault.prepareUnlock()
    screen.vault.armPresenceUnlock()
    Qt.callLater(function() {
      if (!screen.active || screen.vault.status !== "locked") return
      if (screen.vault.pinReady) pinField.forceActiveFocus()
      else passwordField.forceActiveFocus()
    })
  }

  // Centered header matching Panel.qml Screen 2
  Column {
    anchors.horizontalCenter: parent.horizontalCenter
    spacing: Style.space(6)

    Text {
      id: fingerprintIcon
      textFormat: Text.PlainText
      anchors.horizontalCenter: parent.horizontalCenter
      text: screen.vault.fidoScanning ? "󰟵" : (screen.vault.fingerprintScanning ? "󰈷" : "󰌋")
      color: (screen.vault.fingerprintScanning || screen.vault.fidoScanning) ? Color.accent : screen.panel.fg
      opacity: 0.85
      font.family: screen.panel.fontFamily
      font.pixelSize: Style.space(38)

      SequentialAnimation on opacity {
        running: screen.vault.fingerprintScanning || screen.vault.fidoScanning
        loops: Animation.Infinite
        NumberAnimation { to: 0.35; duration: 700; easing.type: Easing.InOutQuad }
        NumberAnimation { to: 0.95; duration: 700; easing.type: Easing.InOutQuad }
        onStopped: fingerprintIcon.opacity = 0.85
      }
    }

    Text {
      textFormat: Text.PlainText
      anchors.horizontalCenter: parent.horizontalCenter
      text: screen.vault.status === "unlocked"
        ? "Loading SSH keys"
        : ((screen.vault.fingerprintReady || screen.vault.fidoReady) ? "Unlock Vault" : "Enter Master Password")
      color: screen.panel.fg
      font.family: screen.panel.fontFamily
      font.pixelSize: Style.font.title
      font.bold: true
    }

    Text {
      textFormat: Text.PlainText
      visible: screen.vault.userEmail !== ""
      anchors.horizontalCenter: parent.horizontalCenter
      text: screen.vault.userEmail
      color: screen.panel.dim
      font.family: screen.panel.fontFamily
      font.pixelSize: Style.font.bodySmall
    }
  }

  UnlockCaption {
    text: {
      var request = screen.vault.sshUnlockRequest
      var prefix = "Vault needs to be unlocked first: "
      if (!request) return "Vault needs to be unlocked first."
      if (request.keyName !== "") {
        return prefix + request.keyName + " is needed by " + request.processName + "."
      }
      return prefix + request.processName + " is asking which SSH keys are available."
    }
    horizontalAlignment: Text.AlignHCenter
    color: screen.panel.fg
  }

  UnlockCaption {
    text: "Unlocking only loads the key. You will still approve the signing request separately."
    horizontalAlignment: Text.AlignHCenter
  }

  // Fingerprint status / prompt
  Text {
    textFormat: Text.PlainText
    visible: screen.vault.fingerprintMessage !== ""
    width: parent.width
    horizontalAlignment: Text.AlignHCenter
    text: screen.vault.fingerprintMessage
    color: screen.vault.fingerprintScanning ? Color.accent : screen.panel.dim
    font.family: screen.panel.fontFamily
    font.pixelSize: Style.font.bodySmall
    wrapMode: Text.WordWrap
  }

  // Offered when fingerprint unlock is on but nothing is stored yet
  Text {
    textFormat: Text.PlainText
    visible: screen.vault.fingerprintUnlock && screen.vault.fingerprintAvailable && !screen.vault.fingerprintStored
    width: parent.width
    horizontalAlignment: Text.AlignHCenter
    text: "󰈷  Unlock once with your master password to enable fingerprint unlock."
    color: screen.panel.dim
    font.family: screen.panel.fontFamily
    font.pixelSize: Style.font.caption
    wrapMode: Text.WordWrap
  }

  // FIDO2 status / prompt, and the same "unlock once" hint the reader gets.
  Text {
    textFormat: Text.PlainText
    visible: screen.vault.fidoMessage !== ""
    width: parent.width
    horizontalAlignment: Text.AlignHCenter
    text: screen.vault.fidoMessage
    color: screen.vault.fidoScanning ? Color.accent : screen.panel.dim
    font.family: screen.panel.fontFamily
    font.pixelSize: Style.font.bodySmall
    wrapMode: Text.WordWrap
  }

  Text {
    textFormat: Text.PlainText
    visible: screen.vault.fidoUnlock && screen.vault.fidoAvailable && !screen.vault.fidoStored
    width: parent.width
    horizontalAlignment: Text.AlignHCenter
    text: "󰟵  Unlock once with your master password to enable FIDO2 unlock."
    color: screen.panel.dim
    font.family: screen.panel.fontFamily
    font.pixelSize: Style.font.caption
    wrapMode: Text.WordWrap
  }

  // Checking / keys loading into helper indicator
  Rectangle {
    visible: screen.vault.status === "checking"
      || (screen.vault.status === "unlocked" && screen.vault.sshAgentLoadActive)
    width: parent.width
    height: loadingText.implicitHeight + Style.space(20)
    radius: Style.cornerRadius
    color: Util.alpha(Color.popups.text, 0.06)

    Text {
      id: loadingText
      textFormat: Text.PlainText
      anchors.centerIn: parent
      width: parent.width - Style.space(24)
      text: screen.vault.status === "checking"
        ? "Checking vault status..."
        : Model.sshAgentLoadingNote()
      color: screen.panel.fg
      font.family: screen.panel.fontFamily
      font.pixelSize: Style.font.bodySmall
      wrapMode: Text.WordWrap
      horizontalAlignment: Text.AlignHCenter
    }
  }

  // PIN entry, offered above the password field when one is set
  Column {
    visible: screen.vault.status === "locked" && screen.vault.pinReady
    width: parent.width
    spacing: Style.space(8)

    Text {
      textFormat: Text.PlainText
      text: "PIN"
      color: screen.panel.dim
      font.family: screen.panel.fontFamily
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
        text: screen.vault.pinEntry
        onTextChanged: screen.vault.pinEntry = text.replace(/[^0-9]/g, "")
        onAccepted: screen.vault.submitPinUnlock()
        enabled: !screen.vault.pinBusy && !screen.vault.isUnlocking
      }

      Button {
        id: pinUnlockBtn
        text: screen.vault.pinBusy ? "Checking..." : "Unlock"
        iconText: screen.vault.pinBusy ? "󰑐" : "󰌿"
        iconSpinning: screen.vault.pinBusy
        selected: true
        accent: Color.accent
        fontFamily: screen.panel.fontFamily
        focusable: true
        enabled: !screen.vault.pinBusy && !screen.vault.isUnlocking
        onClicked: screen.vault.submitPinUnlock()
      }
    }

    Text {
      textFormat: Text.PlainText
      visible: screen.vault.pinError !== ""
      width: parent.width
      text: screen.vault.pinError
      color: screen.panel.urgent
      font.family: screen.panel.fontFamily
      font.pixelSize: Style.font.bodySmall
      wrapMode: Text.WordWrap
    }

    Text {
      textFormat: Text.PlainText
      text: "or use your master password below"
      color: screen.panel.dim
      font.family: screen.panel.fontFamily
      font.pixelSize: Style.font.caption
    }
  }

  // Fingerprint / Password column matching Panel.qml
  Column {
    visible: screen.vault.status === "locked"
    width: parent.width
    spacing: Style.space(10)

    Button {
      visible: screen.vault.fingerprintReady
      width: parent.width
      text: screen.vault.fingerprintScanning ? "Waiting for fingerprint..." : "Unlock with Fingerprint"
      iconText: "󰈷"
      selected: true
      accent: Color.accent
      fontFamily: screen.panel.fontFamily
      focusable: true
      enabled: !screen.vault.isUnlocking && !screen.vault.fingerprintScanning
      onClicked: screen.vault.startFingerprintUnlock()
    }

    Button {
      visible: screen.vault.fidoReady
      width: parent.width
      text: screen.vault.fidoScanning ? "Waiting for your key..." : "Unlock with FIDO2 Key"
      iconText: "󰟵"
      selected: true
      accent: Color.accent
      fontFamily: screen.panel.fontFamily
      focusable: true
      enabled: !screen.vault.isUnlocking && !screen.vault.fidoScanning
      onClicked: screen.vault.startFidoUnlock()
    }

    Row {
      width: parent.width
      spacing: Style.space(8)

      TextField {
        id: passwordField
        width: parent.width - eyeBtnUnlock.width - Style.space(8)
        placeholderText: "Master password..."
        password: !eyeBtnUnlock.revealed
        text: screen.vault.masterPassword
        onTextChanged: screen.vault.masterPassword = text
        onActiveFocusChanged: if (activeFocus) screen.vault.prepareUnlock()
        onAccepted: screen.vault.unlockVault()
        enabled: !screen.vault.isUnlocking
      }

      Button {
        id: eyeBtnUnlock
        property bool revealed: false
        iconText: revealed ? "󰈉" : "󰈈"
        tooltipText: revealed ? "Hide password" : "Show password"
        fontFamily: screen.panel.fontFamily
        focusable: true
        onClicked: revealed = !revealed
      }
    }

    Button {
      width: parent.width
      text: screen.vault.isUnlocking ? "Unlocking..." : "Unlock Vault"
      iconText: screen.vault.isUnlocking ? "󰑐" : "󰌋"
      iconSpinning: screen.vault.isUnlocking
      selected: true
      accent: Color.accent
      fontFamily: screen.panel.fontFamily
      focusable: true
      enabled: !screen.vault.isUnlocking
      onClicked: screen.vault.unlockVault()
    }
  }

  UnlockCaption {
    visible: screen.vault.errorMessage !== ""
    text: screen.vault.errorMessage
    color: screen.panel.urgent
    horizontalAlignment: Text.AlignHCenter
  }

  UnlockCaption {
    visible: screen.vault.status === "unauthenticated"
    text: "Sign in from the Bitwarden panel before using vault SSH keys."
    color: screen.panel.urgent
    horizontalAlignment: Text.AlignHCenter
  }

  Row {
    width: parent.width
    spacing: Style.space(8)

    Button {
      text: "Not now (Esc)"
      iconText: "󰅘"
      fontFamily: screen.panel.fontFamily
      fontSize: Style.font.bodySmall
      focusable: true
      onClicked: screen.vault.denySshRequest()
    }

    Button {
      visible: screen.vault.sshUnlockPendingCount > 1
      text: "Deny all (" + screen.vault.sshUnlockPendingCount + ")"
      iconText: "󰅙"
      fontFamily: screen.panel.fontFamily
      fontSize: Style.font.bodySmall
      focusable: true
      onClicked: screen.vault.denyAllSshRequests()
    }

    Item { width: Math.max(0, parent.width - Style.space(screen.vault.sshUnlockPendingCount > 1 ? 280 : 160)); height: 1 }

    Text {
      textFormat: Text.PlainText
      anchors.verticalCenter: parent.verticalCenter
      text: screen.vault.sshPromptRemainingSec + "s left"
      color: screen.vault.sshPromptRemainingSec <= 5
        ? screen.panel.urgent : screen.panel.dim
      font.family: screen.panel.fontFamily
      font.pixelSize: Style.font.caption
    }
  }
}
