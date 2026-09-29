import QtQuick
import qs.Commons
import qs.Ui

// A form field for a secret that cannot be changed once it leaks (a card
// number or security code, an SSN, a passport or licence number, a TOTP
// seed): masked until its eye is pressed. The item form used plain fields for
// these, which drew them in the clear, offered their text to input methods
// (prediction learns it) and copied a selection to the primary selection.
// Masked, Qt does neither; the hints below keep input methods out while
// revealed too.
TextField {
  id: field

  property bool revealed: false
  property string iconFontFamily: Style.font.family

  password: !revealed
  inputMethodHints: Qt.ImhSensitiveData | Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase
  rightPadding: eye.width + Style.space(12)

  // A reveal lasts only while the field is on screen: leaving the form or
  // switching the item's type masks it again.
  onVisibleChanged: if (!visible) revealed = false

  Button {
    id: eye
    anchors.right: parent.right
    anchors.rightMargin: Style.space(3)
    anchors.verticalCenter: parent.verticalCenter
    iconText: field.revealed ? "󰈉" : "󰈈"
    tooltipText: field.revealed ? "Hide" : "Show"
    fontFamily: field.iconFontFamily
    onClicked: field.revealed = !field.revealed
  }
}
