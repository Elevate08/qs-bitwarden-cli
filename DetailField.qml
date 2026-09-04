import QtQuick
import qs.Commons
import qs.Ui
import "BitwardenModel.js" as Model

// One labelled, copyable field on the detail screen.
//
// The detail view drew each of these longhand -- a PanelSectionHeader, a
// BorderSurface, a Text and one or two PanelActionButtons, forty lines at a
// time. That was tolerable while only a login had fields worth showing.
// Cards and identities together add sixteen more, and sixteen more copies of
// the same forty lines is how the surfaces drift apart: one row elides and
// the next does not, one masks and the next forgets to.
//
// Empty is not a state worth drawing. `visible` is false when there is no
// value, so a caller can declare every field a type can carry and let the
// sparse ones -- most of an identity, most of the time -- take themselves off
// the screen rather than leaving labelled blanks behind.
Column {
  id: root

  required property string label
  required property string value
  required property color foreground
  required property string fontFamily

  // A value that should not sit in plain sight on a shared screen: a card
  // number, a security code, a social security number. Masked until revealed,
  // and the reveal is per-field rather than a screen-wide switch.
  property bool sensitive: false
  property bool revealed: false

  // What the flash message calls this once it is on the clipboard.
  property string copyLabel: label
  // Appended to the copy button's tooltip, e.g. "(n)". Empty when the field
  // has no key bound to it.
  property string shortcutHint: ""
  // The same, for the reveal button. Separate because only one field per item
  // is reachable by `v` -- promising it on the others would be a lie, and the
  // reveal on each field is independent of every other.
  property string revealHint: ""
  // The copy button's glyph. Defaults to a plain copy icon; callers pass a
  // semantic one where the detail view already had it, so a converted row
  // keeps the icon it has always drawn.
  property string copyIcon: "󰈙"

  signal copyRequested()
  signal revealToggled()

  readonly property bool masked: root.sensitive && !root.revealed

  visible: root.value !== ""
  width: parent ? parent.width : 0
  spacing: Style.space(4)

  PanelSectionHeader { text: root.label.toUpperCase() }

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
          tooltipText: (root.revealed ? "Hide " : "Reveal ") + root.copyLabel.toLowerCase()
            + (root.revealHint === "" ? "" : " (" + root.revealHint + ")")
          fontFamily: root.fontFamily
          onClicked: root.revealToggled()
        }

        PanelActionButton {
          iconText: root.copyIcon
          tooltipText: "Copy " + root.copyLabel.toLowerCase()
            + (root.shortcutHint === "" ? "" : " (" + root.shortcutHint + ")")
          fontFamily: root.fontFamily
          onClicked: root.copyRequested()
        }
      }
    }
  }
}
