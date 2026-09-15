import QtQuick
import qs.Commons

// Shared caption used by the SSH screens. Text defaults to AutoText, so the
// format is stated even where the string is constant today. Callers may
// override `color`; the default is the bar's dim foreground.
Text {
  required property var panel

  textFormat: Text.PlainText
  width: parent ? parent.width : 0
  color: panel.dim
  font.family: panel.fontFamily
  font.pixelSize: Style.font.caption
  wrapMode: Text.WordWrap
}
