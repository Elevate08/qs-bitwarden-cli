import QtQuick
import qs.Commons
import qs.Ui
import "BitwardenModel.js" as Model

// The first step of an SSH request when the vault is locked. Uses the shared
// UnlockForm so the popup cannot drift from the panel lock screen.
Column {
  id: screen

  required property var panel
  required property var vault
  property bool active: false

  readonly property alias unlockForm: unlockForm

  visible: active && vault.sshUnlockRequest !== null
  width: parent ? parent.width : 0
  spacing: Style.space(12)

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
    if (screen.vault.fingerprintReady) screen.vault.startFingerprintUnlock()
    Qt.callLater(function() {
      if (!screen.active || !unlockForm.fieldsOffered) return
      if (screen.vault.pinReady) unlockForm.pinField.forceActiveFocus()
      else unlockForm.passwordField.forceActiveFocus()
    })
  }

  function syncFromVault() {
    unlockForm.syncFromVault()
  }

  UnlockForm {
    id: unlockForm
    panel: screen.panel
    vault: screen.vault
    buttonsFocusable: true
    // Until `bw status` answers there is no unlock process to deliver a
    // password to, and a PIN result is discarded, so offer nothing yet; the
    // "Checking vault status..." box says why. Focus follows the fields in.
    fieldsOffered: screen.vault.status === "locked"
    onFieldsOfferedChanged: if (fieldsOffered) screen.focusDefault()

    context: [
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
      },

      UnlockCaption {
        text: "Unlocking only loads the key. You will still approve the signing request separately."
        horizontalAlignment: Text.AlignHCenter
      },

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
    ]
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
