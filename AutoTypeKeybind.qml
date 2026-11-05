import QtQuick
import qs.Commons
import qs.Ui
import "BitwardenModel.js" as Model

// Under "Auto-type logins" while it is on: which key runs the autoType IPC,
// and registering one in ~/.config/hypr/bindings.lua (see "Auto-type
// keybinding" in BitwardenModel.js). Stateless; reads the vault and calls back
// into it.
Column {
  id: section

  required property var panel
  // The vault this panel shows (Service.qml); `panel` is the view that draws it.
  required property var vault

  readonly property var keybind: section.vault.autoTypeKeybind
  readonly property var chordCheck: section.vault.autoTypeChordCheck
  // The field and its buttons, while no key runs auto-type yet.
  readonly property bool choosing: section.keybind.checked && !section.keybind.bound

  width: parent ? parent.width : 0
  spacing: Style.space(6)

  Item { width: parent.width; height: Style.space(4) }

  PanelSectionHeader {
    textFormat: Text.PlainText
    text: "AUTO-TYPE KEY"
    foreground: section.panel.fg
    fontFamily: section.panel.fontFamily
  }

  Row {
    width: parent.width
    spacing: Style.space(8)

    Text {
      id: keybindIcon
      textFormat: Text.PlainText
      anchors.verticalCenter: parent.verticalCenter
      text: section.keybind.bound ? "󰄬" : "󰌌"
      color: section.keybind.bound && section.keybind.live !== false ? Color.accent : section.panel.dim
      font.family: section.panel.fontFamily
      font.pixelSize: Style.font.body
    }

    Text {
      textFormat: Text.PlainText
      anchors.verticalCenter: parent.verticalCenter
      width: parent.width - keybindIcon.width - parent.spacing
      text: section.keybind.status
      color: section.keybind.bound ? section.panel.fg : section.panel.dim
      font.family: section.panel.fontFamily
      font.pixelSize: Style.font.bodySmall
      wrapMode: Text.WordWrap
    }
  }

  SshCaption {
    panel: section.panel
    visible: section.keybind.detail !== ""
    text: section.keybind.detail
  }

  // Why the plugin will not write the file; Copy Line still works.
  SshCaption {
    panel: section.panel
    visible: section.keybind.blocked !== ""
    text: section.keybind.blocked
    color: section.panel.urgent
  }

  LineField {
    id: chordField
    visible: section.choosing
    width: parent.width
    placeholderText: Model.autoTypeChordSuggestions()[0]
    text: section.vault.autoTypeChordText
    onTextChanged: section.vault.autoTypeChordText = text
    // Return registers; there is no form around it to submit.
    submitsForm: false
    onAccepted: section.vault.registerAutoTypeKeybind()
    enabled: !section.vault.autoTypeKeybindBusy
    inputMethodHints: Qt.ImhNoPredictiveText | Qt.ImhPreferUppercase
    // Escape leaves the field for the settings list, as it does nowhere else
    // on this screen.
    Keys.onEscapePressed: function(event) {
      section.vault.restoreScreenFocus()
      event.accepted = true
    }
  }

  // An invalid chord or a key something else already has.
  SshCaption {
    panel: section.panel
    visible: section.choosing && !section.chordCheck.ok && section.vault.autoTypeChordText !== ""
    text: section.chordCheck.message
    color: section.panel.urgent
  }

  SshCaption {
    panel: section.panel
    visible: section.choosing && section.chordCheck.note !== ""
    text: section.chordCheck.note
  }

  // A Flow: which buttons show depends on the state.
  Flow {
    width: parent.width
    spacing: Style.space(8)

    Button {
      visible: section.choosing && section.keybind.canRegister
      text: "Register Keybinding"
      iconText: "󰌌"
      tooltipText: "Add this key to " + Model.autoTypeBindingsDisplayPath() + " and reload Hyprland"
      fontFamily: section.panel.fontFamily
      fontSize: Style.font.bodySmall
      enabled: section.chordCheck.ok && !section.vault.autoTypeKeybindBusy
      onClicked: section.vault.registerAutoTypeKeybind()
    }

    // For bindings kept somewhere else; the line is not a secret.
    Button {
      visible: section.choosing
      text: "Copy Line"
      iconText: "󰆏"
      tooltipText: section.chordCheck.line !== "" ? section.chordCheck.line : "Type a valid key combination first"
      fontFamily: section.panel.fontFamily
      fontSize: Style.font.bodySmall
      enabled: section.chordCheck.line !== ""
      onClicked: section.vault.copyAutoTypeBindLine()
    }

    // Only the two lines this plugin wrote, exactly as it wrote them.
    Button {
      visible: section.keybind.bound && section.keybind.removable === true
      text: "Remove Keybinding"
      iconText: "󰩹"
      tooltipText: "Delete the lines this plugin added to " + Model.autoTypeBindingsDisplayPath()
      fontFamily: section.panel.fontFamily
      fontSize: Style.font.bodySmall
      enabled: !section.vault.autoTypeKeybindBusy
      onClicked: section.vault.removeAutoTypeKeybind()
    }
  }

  SshCaption {
    panel: section.panel
    visible: section.vault.autoTypeKeybindResult !== null
    text: section.vault.autoTypeKeybindResult ? section.vault.autoTypeKeybindResult.message : ""
    color: section.vault.autoTypeKeybindResult && section.vault.autoTypeKeybindResult.ok && !section.vault.autoTypeKeybindResult.warning
      ? section.panel.fg : section.panel.urgent
  }
}
