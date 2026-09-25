import QtQuick
import qs.Commons
import qs.Ui

// Bitwarden's master password re-prompt: an item with the flag asks for the
// master password before any of its secrets is shown, copied or edited. The
// vault runs the check (withReprompt() holds the action, submitReprompt()
// verifies, cancelReprompt() drops it); this only collects the password.
//
// Overlaid on the panel content with a scrim, so nothing underneath can be
// clicked while it asks. Enter submits, Escape cancels.
Item {
  id: confirm

  required property var panel
  // The vault this panel shows (Service.qml); `panel` is the view that draws it.
  required property var vault

  readonly property bool shown: vault.repromptPending === true
  // The vault is checking the password it was handed. The field is disabled
  // meanwhile, which takes its focus; a wrong password gives it back.
  readonly property bool busy: vault.repromptBusy === true
  onBusyChanged: if (!busy && shown) Qt.callLater(function() { if (confirm.shown) passwordField.forceActiveFocus() })

  visible: shown
  z: 30

  function submit() {
    if (confirm.busy || passwordField.text === "") return
    var typed = passwordField.text
    // Not kept in the field once handed over, right or wrong.
    passwordField.text = ""
    confirm.vault.submitReprompt(typed)
  }

  function cancel() {
    passwordField.text = ""
    confirm.vault.cancelReprompt()
  }

  onShownChanged: {
    passwordField.text = ""
    if (shown) {
      Qt.callLater(function() { if (confirm.shown) passwordField.forceActiveFocus() })
    } else {
      // Back to whatever the screen underneath focuses.
      confirm.vault.restoreScreenFocus()
    }
  }

  Rectangle {
    anchors.fill: parent
    color: Color.menu.scrim
  }

  // Nothing underneath is reachable while the question is open.
  MouseArea {
    anchors.fill: parent
    acceptedButtons: Qt.AllButtons
    hoverEnabled: true
  }

  BorderSurface {
    id: card
    anchors.centerIn: parent
    width: Math.min(parent.width - Style.space(24), Style.space(380))
    implicitHeight: content.implicitHeight + Style.space(24)
    radius: Style.cornerRadius
    color: Color.popups.background
    borderSpec: Border.surfaceSpec("popups", "border", Color.accent, 1)

    Column {
      id: content
      anchors.centerIn: parent
      width: parent.width - Style.space(24)
      spacing: Style.space(10)

      Text {
        textFormat: Text.PlainText
        width: parent.width
        text: "\u{F033E}  Master password required"
        color: Color.accent
        font.family: confirm.panel.fontFamily
        font.pixelSize: Style.font.body
        font.bold: true
      }

      Text {
        textFormat: Text.PlainText
        width: parent.width
        text: (confirm.vault.repromptItemName ? confirm.vault.repromptItemName : "This item")
          + " asks for your master password before its secrets are shown, copied or edited."
        color: confirm.panel.fg
        font.family: confirm.panel.fontFamily
        font.pixelSize: Style.font.bodySmall
        wrapMode: Text.WordWrap
      }

      TextField {
        id: passwordField
        width: parent.width
        placeholderText: "Master password..."
        password: true
        inputMethodHints: Qt.ImhSensitiveData | Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase
        enabled: !confirm.busy
        onAccepted: confirm.submit()
        // Taken here: the panel's own Escape would leave the screen.
        Keys.onEscapePressed: function(event) {
          event.accepted = true
          confirm.cancel()
        }
      }

      Text {
        textFormat: Text.PlainText
        visible: String(confirm.vault.repromptError || "") !== ""
        width: parent.width
        text: String(confirm.vault.repromptError || "")
        color: confirm.panel.urgent
        font.family: confirm.panel.fontFamily
        font.pixelSize: Style.font.bodySmall
        wrapMode: Text.WordWrap
      }

      Row {
        spacing: Style.space(8)

        Button {
          text: confirm.busy ? "Checking..." : "Confirm"
          iconText: confirm.busy ? "\u{F0450}" : "\u{F012C}"
          iconSpinning: confirm.busy
          selected: true
          accent: Color.accent
          fontFamily: confirm.panel.fontFamily
          fontSize: Style.font.bodySmall
          enabled: !confirm.busy && passwordField.text !== ""
          onClicked: confirm.submit()
        }

        Button {
          text: "Cancel (Esc)"
          iconText: "\u{F0156}"
          fontFamily: confirm.panel.fontFamily
          fontSize: Style.font.bodySmall
          onClicked: confirm.cancel()
        }
      }
    }
  }
}
