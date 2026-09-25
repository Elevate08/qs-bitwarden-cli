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

  // Like the approval card (see SshApprovalScreen.qml): the request can
  // arrive mid-typing, and focus used to land straight in the PIN or
  // password field, so stray keys and an Enter submitted them (five wrong
  // PINs remove PIN unlock; part of a sudo password could reach `bw unlock`).
  // For armDelayMs after the card appears, its request or the vault's status
  // changes, or the popup takes focus, the guard holds the keyboard and drops
  // everything but Escape; then the field gets focus.
  readonly property int armDelayMs: 800
  property bool armed: false
  readonly property bool shown: active && visible

  function rearm() {
    screen.armed = false
    if (!screen.shown) {
      armTimer.stop()
      return
    }
    armTimer.restart()
    keyGuard.forceActiveFocus()
  }

  function focusDefault() {
    if (!screen.active || !screen.visible) return
    screen.vault.prepareUnlock()
    screen.vault.armPresenceUnlock()
    screen.focusField()
  }

  // The unlock field once armed; the guard until then (the timer comes back).
  function focusField() {
    if (!screen.armed) {
      keyGuard.forceActiveFocus()
      return
    }
    Qt.callLater(function() {
      if (!screen.active || !screen.armed || !unlockForm.fieldsOffered) return
      if (unlockForm.focusField) unlockForm.focusField.forceActiveFocus()
    })
  }

  onShownChanged: rearm()
  // A Loader may build the card already shown, when no change is signalled.
  Component.onCompleted: rearm()

  Connections {
    target: screen.vault
    function onSshUnlockRequestChanged() { screen.rearm() }
    function onStatusChanged() { screen.rearm() }
  }

  Timer {
    id: armTimer
    interval: screen.armDelayMs
    onTriggered: {
      screen.armed = true
      if (keyGuard.activeFocus) screen.focusField()
    }
  }

  // Zero-sized, so the Column does not lay it out.
  Item {
    id: keyGuard
    width: 0
    height: 0
    Keys.onPressed: function(event) {
      if (event.key === Qt.Key_Escape) return
      if (!screen.armed) event.accepted = true
    }
  }

  function syncFromVault() {
    unlockForm.syncFromVault()
  }

  UnlockForm {
    id: unlockForm
    panel: screen.panel
    vault: screen.vault
    buttonsFocusable: true
    // Nothing to unlock until `bw status` answers; the "Checking vault
    // status..." box says so. Focus follows the fields in.
    fieldsOffered: screen.vault.status === "locked"
    onFieldsOfferedChanged: if (fieldsOffered) screen.focusDefault()

    context: [
      // Who is asking, and for what.
      SshCaption {
        panel: screen.panel
        text: {
          var request = screen.vault.sshUnlockRequest
          if (!request) return ""
          if (request.keyName !== "") {
            return request.keyName + " is needed by " + request.processName + "."
          }
          return request.processName + " is asking which SSH keys are available."
        }
        horizontalAlignment: Text.AlignHCenter
        color: screen.panel.fg
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

  SshCaption {
    panel: screen.panel
    visible: screen.vault.errorMessage !== ""
    text: screen.vault.errorMessage
    color: screen.panel.urgent
    horizontalAlignment: Text.AlignHCenter
  }

  SshCaption {
    panel: screen.panel
    visible: screen.vault.status === "unauthenticated"
    text: "Sign in from the Bitwarden panel before using vault SSH keys."
    color: screen.panel.urgent
    horizontalAlignment: Text.AlignHCenter
  }

  Row {
    width: parent.width
    spacing: Style.space(8)

    Button {
      text: "Not now"
      iconText: "󰅖"
      tooltipText: "Refuse this request (Esc)"
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
