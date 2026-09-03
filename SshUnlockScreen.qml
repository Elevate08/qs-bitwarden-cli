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
  property bool active: false

  visible: active && panel.sshUnlockRequest !== null
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
    screen.panel.prepareUnlock()
    if (screen.panel.fingerprintReady) screen.panel.startFingerprintUnlock()
    Qt.callLater(function() {
      if (!screen.active || screen.panel.status !== "locked") return
      if (screen.panel.pinReady) pinField.forceActiveFocus()
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
      text: screen.panel.fingerprintScanning ? "󰈷" : "󰌋"
      color: screen.panel.fingerprintScanning ? Color.accent : screen.panel.fg
      opacity: 0.85
      font.family: screen.panel.fontFamily
      font.pixelSize: Style.space(38)

      SequentialAnimation on opacity {
        running: screen.panel.fingerprintScanning
        loops: Animation.Infinite
        NumberAnimation { to: 0.35; duration: 700; easing.type: Easing.InOutQuad }
        NumberAnimation { to: 0.95; duration: 700; easing.type: Easing.InOutQuad }
        onStopped: fingerprintIcon.opacity = 0.85
      }
    }

    Text {
      textFormat: Text.PlainText
      anchors.horizontalCenter: parent.horizontalCenter
      text: screen.panel.status === "unlocked"
        ? "Loading SSH keys"
        : (screen.panel.fingerprintReady ? "Unlock Vault" : "Enter Master Password")
      color: screen.panel.fg
      font.family: screen.panel.fontFamily
      font.pixelSize: Style.font.title
      font.bold: true
    }

    Text {
      textFormat: Text.PlainText
      visible: screen.panel.userEmail !== ""
      anchors.horizontalCenter: parent.horizontalCenter
      text: screen.panel.userEmail
      color: screen.panel.dim
      font.family: screen.panel.fontFamily
      font.pixelSize: Style.font.bodySmall
    }
  }

  UnlockCaption {
    text: {
      var request = screen.panel.sshUnlockRequest
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
    visible: screen.panel.fingerprintMessage !== ""
    width: parent.width
    horizontalAlignment: Text.AlignHCenter
    text: screen.panel.fingerprintMessage
    color: screen.panel.fingerprintScanning ? Color.accent : screen.panel.dim
    font.family: screen.panel.fontFamily
    font.pixelSize: Style.font.bodySmall
    wrapMode: Text.WordWrap
  }

  // Offered when fingerprint unlock is on but nothing is stored yet
  Text {
    textFormat: Text.PlainText
    visible: screen.panel.fingerprintUnlock && screen.panel.fingerprintAvailable && !screen.panel.fingerprintStored
    width: parent.width
    horizontalAlignment: Text.AlignHCenter
    text: "󰈷  Unlock once with your master password to enable fingerprint unlock."
    color: screen.panel.dim
    font.family: screen.panel.fontFamily
    font.pixelSize: Style.font.caption
    wrapMode: Text.WordWrap
  }

  // Checking / keys loading into helper indicator
  Rectangle {
    visible: screen.panel.status === "checking"
      || (screen.panel.status === "unlocked" && screen.panel.sshAgentLoadActive)
    width: parent.width
    height: loadingText.implicitHeight + Style.space(20)
    radius: Style.cornerRadius
    color: Util.alpha(Color.popups.text, 0.06)

    Text {
      id: loadingText
      textFormat: Text.PlainText
      anchors.centerIn: parent
      width: parent.width - Style.space(24)
      text: screen.panel.status === "checking"
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
    visible: screen.panel.status === "locked" && screen.panel.pinReady
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
        text: screen.panel.pinEntry
        onTextChanged: screen.panel.pinEntry = text.replace(/[^0-9]/g, "")
        onAccepted: screen.panel.submitPinUnlock()
        enabled: !screen.panel.pinBusy && !screen.panel.isUnlocking
      }

      Button {
        id: pinUnlockBtn
        text: screen.panel.pinBusy ? "Checking..." : "Unlock"
        iconText: screen.panel.pinBusy ? "󰑐" : "󰌿"
        iconSpinning: screen.panel.pinBusy
        selected: true
        accent: Color.accent
        fontFamily: screen.panel.fontFamily
        focusable: true
        enabled: !screen.panel.pinBusy && !screen.panel.isUnlocking
        onClicked: screen.panel.submitPinUnlock()
      }
    }

    Text {
      textFormat: Text.PlainText
      visible: screen.panel.pinError !== ""
      width: parent.width
      text: screen.panel.pinError
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
    visible: screen.panel.status === "locked"
    width: parent.width
    spacing: Style.space(10)

    Button {
      visible: screen.panel.fingerprintReady
      width: parent.width
      text: screen.panel.fingerprintScanning ? "Waiting for fingerprint..." : "Unlock with Fingerprint"
      iconText: "󰈷"
      selected: true
      accent: Color.accent
      fontFamily: screen.panel.fontFamily
      focusable: true
      enabled: !screen.panel.isUnlocking && !screen.panel.fingerprintScanning
      onClicked: screen.panel.startFingerprintUnlock()
    }

    Row {
      width: parent.width
      spacing: Style.space(8)

      TextField {
        id: passwordField
        width: parent.width - eyeBtnUnlock.width - Style.space(8)
        placeholderText: "Master password..."
        password: !eyeBtnUnlock.revealed
        text: screen.panel.masterPassword
        onTextChanged: screen.panel.masterPassword = text
        onActiveFocusChanged: if (activeFocus) screen.panel.prepareUnlock()
        onAccepted: screen.panel.unlockVault()
        enabled: !screen.panel.isUnlocking
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
      text: screen.panel.isUnlocking ? "Unlocking..." : "Unlock Vault"
      iconText: screen.panel.isUnlocking ? "󰑐" : "󰌋"
      iconSpinning: screen.panel.isUnlocking
      selected: true
      accent: Color.accent
      fontFamily: screen.panel.fontFamily
      focusable: true
      enabled: !screen.panel.isUnlocking
      onClicked: screen.panel.unlockVault()
    }
  }

  UnlockCaption {
    visible: screen.panel.errorMessage !== ""
    text: screen.panel.errorMessage
    color: screen.panel.urgent
    horizontalAlignment: Text.AlignHCenter
  }

  UnlockCaption {
    visible: screen.panel.status === "unauthenticated"
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
      onClicked: screen.panel.denySshRequest()
    }

    Button {
      visible: screen.panel.sshUnlockPendingCount > 1
      text: "Deny all (" + screen.panel.sshUnlockPendingCount + ")"
      iconText: "󰅙"
      fontFamily: screen.panel.fontFamily
      fontSize: Style.font.bodySmall
      focusable: true
      onClicked: screen.panel.denyAllSshRequests()
    }

    Item { width: Math.max(0, parent.width - Style.space(screen.panel.sshUnlockPendingCount > 1 ? 280 : 160)); height: 1 }

    Text {
      textFormat: Text.PlainText
      anchors.verticalCenter: parent.verticalCenter
      text: screen.panel.sshPromptRemainingSec + "s left"
      color: screen.panel.sshPromptRemainingSec <= 5
        ? screen.panel.urgent : screen.panel.dim
      font.family: screen.panel.fontFamily
      font.pixelSize: Style.font.caption
    }
  }
}
