import QtQuick
import qs.Commons

// A screen's title and the explanation under it, in the bar's foreground and
// font.
Column {
  id: intro

  required property var panel
  property string title: ""
  property string body: ""

  spacing: Style.space(4)

  Text {
    textFormat: Text.PlainText
    text: intro.title
    color: intro.panel.fg
    font.family: intro.panel.fontFamily
    font.pixelSize: Style.font.title
    font.bold: true
  }

  Text {
    textFormat: Text.PlainText
    width: parent.width
    text: intro.body
    color: intro.panel.dim
    font.family: intro.panel.fontFamily
    font.pixelSize: Style.font.bodySmall
    wrapMode: Text.WordWrap
  }
}
