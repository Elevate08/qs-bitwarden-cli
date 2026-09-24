import QtQuick
import qs.Commons

// Caption text for the SSH screens, in the bar's dim foreground by default.
Text {
  required property var panel

  textFormat: Text.PlainText
  width: parent ? parent.width : 0
  color: panel.dim
  font.family: panel.fontFamily
  font.pixelSize: Style.font.caption
  wrapMode: Text.WordWrap
}
