import QtQuick
import qs.Commons
import qs.Ui

// The SSH sections' own section header. PanelSectionHeader defaults to the
// global theme; everything around it follows the bar's foreground and font.
PanelSectionHeader {
  required property var panel
  textFormat: Text.PlainText
  foreground: panel.fg
  fontFamily: panel.fontFamily
}
