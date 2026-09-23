import QtQuick
import qs.Commons
import qs.Ui
import "BitwardenModel.js" as Model

// One labelled, copyable field on the detail screen. Hidden when the value is
// empty, so callers can declare every field a type can have.
Column {
  id: root

  required property string label
  required property string value
  required property color foreground
  required property string fontFamily

  // Masked until revealed, per field (card numbers, codes, SSNs).
  property bool sensitive: false
  property bool revealed: false

  // How the copy flash message names the field.
  property string copyLabel: label
  // Shortcut hints appended to the copy and reveal tooltips, e.g. "(n)"; empty
  // when no key is bound.
  property string shortcutHint: ""
  property string revealHint: ""
  property string copyIcon: "󰈙"

  signal copyRequested()
  signal revealToggled()

  readonly property bool masked: root.sensitive && !root.revealed

  visible: root.value !== ""
  width: parent ? parent.width : 0
  spacing: Style.space(4)

  PanelSectionHeader {
    text: root.label.toUpperCase()
    width: parent.width
    wrapMode: Text.Wrap
  }

  BorderSurface {
    width: parent.width
    implicitHeight: Style.space(34)
    radius: Style.cornerRadius
    color: Style.hoverFillFor(root.foreground, Color.accent)
    borderSpec: Border.controlSpec("normal", root.foreground, Color.accent)

    Row {
      anchors.fill: parent
      anchors.leftMargin: Style.space(10)
      anchors.rightMargin: Style.space(6)

      Text {
        textFormat: Text.PlainText
        anchors.verticalCenter: parent.verticalCenter
        text: root.masked ? Model.maskString(root.value) : root.value
        color: root.foreground
        font.family: root.fontFamily
        font.pixelSize: Style.font.body
        elide: Text.ElideRight
        width: parent.width - fieldActions.width - Style.space(10)
      }

      Row {
        id: fieldActions
        anchors.verticalCenter: parent.verticalCenter
        spacing: Style.space(4)

        PanelActionButton {
          visible: root.sensitive
          iconText: root.revealed ? "󰈉" : "󰈈"
          tooltipText: Model.plainLabel((root.revealed ? "Hide " : "Reveal ")
            + root.copyLabel.toLowerCase()
            + (root.revealHint === "" ? "" : " (" + root.revealHint + ")"))
          fontFamily: root.fontFamily
          onClicked: root.revealToggled()
        }

        PanelActionButton {
          iconText: root.copyIcon
          tooltipText: Model.plainLabel("Copy " + root.copyLabel.toLowerCase()
            + (root.shortcutHint === "" ? "" : " (" + root.shortcutHint + ")"))
          fontFamily: root.fontFamily
          onClicked: root.copyRequested()
        }
      }
    }
  }
}
