import QtQuick
import qs.Commons
import qs.Ui

// One row in an item-form picker: folder, organization, or collection.
//
// `multi` distinguishes the two behaviours. A folder or organization is a
// single choice, so its mark is a tick; a collection is one of several an item
// may belong to, so its mark is a checkbox that reads as toggleable.
BorderSurface {
  id: row

  property string label: ""
  property string glyph: ""
  property bool picked: false
  property bool multi: false
  property color foreground: Color.foreground
  property string fontFamily: Style.font.family

  signal activated()

  implicitHeight: Style.space(28)
  radius: Style.cornerRadius
  color: picked ? Style.selectedFillFor(foreground, Color.accent)
       : (mouse.containsMouse ? Style.hoverFillFor(foreground, Color.accent) : "transparent")
  borderSpec: Border.surfaceSpec("menu", "border", picked ? Color.accent : "transparent", picked ? 1 : 0)

  MouseArea {
    id: mouse
    anchors.fill: parent
    hoverEnabled: true
    cursorShape: Qt.PointingHandCursor
    onClicked: row.activated()
  }

  Row {
    anchors.fill: parent
    anchors.leftMargin: Style.space(9)
    anchors.rightMargin: Style.space(9)
    spacing: Style.space(8)

    Text {
      anchors.verticalCenter: parent.verticalCenter
      text: row.glyph
      color: row.picked ? Color.accent : Qt.darker(row.foreground, 1.5)
      font.family: row.fontFamily
      font.pixelSize: Style.font.bodySmall
    }

    Text {
      anchors.verticalCenter: parent.verticalCenter
      width: parent.width - Style.space(46)
      text: row.label
      color: row.picked ? Color.accent : row.foreground
      font.family: row.fontFamily
      font.pixelSize: Style.font.bodySmall
      font.bold: row.picked
      elide: Text.ElideRight
    }

    Text {
      anchors.verticalCenter: parent.verticalCenter
      visible: row.multi || row.picked
      text: row.multi ? (row.picked ? "󰄲" : "󰄱") : "󰄬"
      color: row.picked ? Color.accent : Qt.darker(row.foreground, 1.6)
      font.family: row.fontFamily
      font.pixelSize: Style.font.bodySmall
    }
  }
}
