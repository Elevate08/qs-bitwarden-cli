import QtQuick
import qs.Commons
import qs.Ui

// SCREEN: FIDO2 unlock setup, from the Security settings. Asks for the master
// password once and adds a FIDO2 way into the quick-unlock envelope, opened
// later by a key touch. Without an Omarchy key registration it hands off to
// `omarchy setup security fido2`, which also wires the system's own prompts.
// Stateless: edits the vault's setup fields and calls back.
Column {
  id: screen

  required property var panel
  required property var vault
  property bool active: vault.activeScreen === "fido"

  // Focuses its own field (restoreScreenFocus leaves setup forms alone).
  onActiveChanged: {
    if (!active) return
    Qt.callLater(function() {
      if (!screen.active || !screen.visible) return
      if (screen.vault.fidoAvailable) masterField.forceActiveFocus()
    })
  }

  visible: active
  width: parent.width
  spacing: Style.space(12)

  PanelSeparator { width: parent.width }

  Column {
    width: parent.width
    spacing: Style.space(4)

    Text {
      textFormat: Text.PlainText
      text: "Enable FIDO2 unlock"
      color: panel.fg
      font.family: panel.fontFamily
      font.pixelSize: Style.font.title
      font.bold: true
    }

    Text {
      textFormat: Text.PlainText
      width: parent.width
      text: "Your master password is already stored encrypted and sealed to this machine. A touch asks the key for a secret only it can produce, and enabling this lets that secret open the password, so unlocking needs the key itself."
      color: panel.dim
      font.family: panel.fontFamily
      font.pixelSize: Style.font.bodySmall
      wrapMode: Text.WordWrap
    }
  }

  // No key registered by Omarchy yet.
  Column {
    visible: !vault.fidoAvailable
    width: parent.width
    spacing: Style.space(8)

    Text {
      textFormat: Text.PlainText
      width: parent.width
      text: "No FIDO2 key is registered on this machine yet. Omarchy's setup detects the key, registers it, and wires it for the system's own authentication prompts too -- the same registration this vault uses."
      color: panel.dim
      font.family: panel.fontFamily
      font.pixelSize: Style.font.bodySmall
      wrapMode: Text.WordWrap
    }

    Row {
      width: parent.width
      spacing: Style.space(8)

      Button {
        text: "Set up FIDO2"
        iconText: "󰟵"
        selected: true
        accent: Color.accent
        fontFamily: panel.fontFamily
        onClicked: vault.runFidoSetup()
      }

      Button {
        text: "Cancel"
        iconText: "󰅖"
        fontFamily: panel.fontFamily
        onClicked: { vault.fidoSetupError = ""; vault.currentScreen = "settings" }
      }
    }
  }

  // A key is registered: take the master password once.
  Column {
    visible: vault.fidoAvailable
    width: parent.width
    spacing: Style.space(8)

    Text {
      textFormat: Text.PlainText
      text: "MASTER PASSWORD"
      color: panel.dim
      font.family: panel.fontFamily
      font.pixelSize: Style.font.caption
      font.bold: true
    }

    TextField {
      id: masterField
      width: parent.width
      placeholderText: "Needed once, to store for FIDO2 unlock..."
      password: true
      text: vault.fidoSetupMaster
      onTextChanged: vault.fidoSetupMaster = text
      onAccepted: vault.submitFidoSetup()
      enabled: !vault.fidoBusy
    }

    Text {
      textFormat: Text.PlainText
      visible: vault.fidoSetupError !== ""
      width: parent.width
      text: vault.fidoSetupError
      color: Color.urgent
      font.family: panel.fontFamily
      font.pixelSize: Style.font.bodySmall
      wrapMode: Text.WordWrap
    }

    Row {
      width: parent.width
      spacing: Style.space(8)

      Button {
        text: vault.fidoBusy ? "Saving..." : "Enable"
        iconText: vault.fidoBusy ? "󰑐" : "󰟵"
        iconSpinning: vault.fidoBusy
        selected: true
        accent: Color.accent
        fontFamily: panel.fontFamily
        enabled: !vault.fidoBusy
        onClicked: vault.submitFidoSetup()
      }

      Button {
        text: "Cancel"
        iconText: "󰅖"
        fontFamily: panel.fontFamily
        enabled: !vault.fidoBusy
        onClicked: { vault.fidoSetupError = ""; vault.currentScreen = "settings" }
      }
    }
  }
}
