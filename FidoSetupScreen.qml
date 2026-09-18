import QtQuick
import qs.Commons
import qs.Ui

// SCREEN: FIDO2 unlock setup.
//
// Reached from the Security settings row. It asks for the master password once
// -- the way the PIN and fingerprint forms do -- and stores it in the OS login
// keyring, to be released to `bw unlock` only after a key touch has been
// verified. A FIDO2 key cannot produce the master password any more than a
// fingerprint can, so the same presence-gate trade applies; the copy states it
// where the decision is made.
//
// When Omarchy has not registered a key on this machine yet, the form stands
// down and hands off to Omarchy's own setup, which registers the key and wires
// it for the system's own authentication prompts as well -- the same
// registration this vault reads.
//
// `panel` is the Panel root; `vault` is the Service.qml the panel draws. The
// screen holds no state: it edits the vault's setup fields and calls back.
Column {
  id: screen

  required property var panel
  required property var vault
  property bool active: vault.activeScreen === "fido"

  // The form opens on its own field. Service.qml's restoreScreenFocus leaves
  // this screen alone for the same reason it leaves the PIN and fingerprint
  // forms alone: each one focuses itself.
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
      text: "A FIDO2 key proves you are present but cannot produce your master password, and bw unlock accepts nothing else. The password is stored in the OS login keyring, and a verified key touch is the gate on reading it back."
      color: panel.dim
      font.family: panel.fontFamily
      font.pixelSize: Style.font.bodySmall
      wrapMode: Text.WordWrap
    }

    Text {
      textFormat: Text.PlainText
      width: parent.width
      text: "Anyone who can read your unlocked login keyring can read the password. A PIN stores it encrypted instead."
      color: Color.urgent
      font.family: panel.fontFamily
      font.pixelSize: Style.font.caption
      wrapMode: Text.WordWrap
    }
  }

  // Nothing to store behind yet: Omarchy has not registered a key here.
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
