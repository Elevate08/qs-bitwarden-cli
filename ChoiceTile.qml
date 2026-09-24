import QtQuick
import qs.Commons
import qs.Ui

// One option in a row of equal-width choices: its icon over a short label.
// The row sets the width; the unlock methods and the SSH approval decisions
// both use it, so the two rows look alike.
Button {
  id: tile

  required property var panel
  property string glyph: ""
  property string label: ""

  height: tileColumn.implicitHeight + Style.space(12)
  bordered: true
  accent: Color.accent
  fontFamily: tile.panel.fontFamily

  readonly property color _labelColor: tile.selected
    ? Style.selectedStateColor(tile.foreground, tile.accent) : tile.foreground

  Column {
    id: tileColumn
    anchors.centerIn: parent
    width: parent.width - Style.space(8)
    spacing: Style.space(2)

    Text {
      textFormat: Text.PlainText
      anchors.horizontalCenter: parent.horizontalCenter
      text: tile.glyph
      color: tile._labelColor
      font.family: tile.panel.fontFamily
      font.pixelSize: Style.font.title
    }

    Text {
      textFormat: Text.PlainText
      width: parent.width
      horizontalAlignment: Text.AlignHCenter
      text: tile.label
      color: tile._labelColor
      font.family: tile.panel.fontFamily
      font.pixelSize: Style.font.caption
      font.bold: tile.selected
      elide: Text.ElideRight
    }
  }
}
