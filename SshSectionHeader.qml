import QtQuick
import qs.Commons
import qs.Ui

// PanelSectionHeader in the bar's foreground and font.
PanelSectionHeader {
  required property var panel
  textFormat: Text.PlainText
  foreground: panel.fg
  fontFamily: panel.fontFamily
}
