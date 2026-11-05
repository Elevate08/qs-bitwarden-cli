import QtQuick
import qs.Commons
import qs.Commons as Commons
import qs.Ui
import ".."

// The plugin's pinentry prompt (omarchy-pinentry, PinentryPrompt.qml):
// the shell's polkit prompt, drawn the same way from the same theme values
// (`[polkit]` in the theme's shell.toml, the system font, the border spec and
// Hyprland's rounding). A translucent scrim over the whole surface, a card
// with a padlock and a masked field, the description above it, and the
// error of a retry above the field in the error colour.
//
// The padlock shows what is typed and hides it again, and gives the field
// its focus back. Enter submits (accepted()), Escape cancels (rejected());
// either, and open(), mask the field again. Fills its parent.
//
// The field is the panel's LineField, unframed, not polkit's TextInput: on
// Qt 6.12 an editable TextInput reads every new clipboard offer into this
// process on the GUI thread (see LineField.qml), and the clipboard is where
// the panel puts a copied password. Paste goes through LineField's capped
// wl-paste.
Item {
  id: root

  property string description: ""
  property string prompt: ""
  property string error: ""

  property string fontFamily: Style.font.menuFamily
  property color accent: Commons.Color.polkit.accent
  property color background: Commons.Color.polkit.background
  property color foreground: Commons.Color.polkit.text
  property color textError: Commons.Color.polkit.textError
  property color border: Commons.Color.polkit.border
  property color borderError: Commons.Color.polkit.borderError
  property color scrim: Commons.Color.polkit.scrim
  property var borderSpec: Border.surfaceSpec("polkit", errorFlash ? "border-error" : "border",
    errorFlash ? borderError : border, Math.max(1, Style.space(2)), "border-alpha")
  readonly property int cornerRadius: Style.cornerRadius
  property int contentMargin: Style.spacing.panelPadding
  property int fieldHeight: Math.max(Style.space(42), Style.spacing.controlHeight)

  // What is typed, shown as typed rather than masked.
  property bool revealed: false
  // Submitted or cancelled: the field takes nothing more.
  property bool done: false
  property bool errorFlash: false
  property int shakeOffset: 0

  readonly property int cardHeight: height > 0 ? Math.min(fieldHeight + contentMargin * 2, height - Style.gapsOut * 2) : fieldHeight + contentMargin * 2
  readonly property int cardWidth: Math.min(Style.space(312), Math.max(Style.space(260), width - Style.gapsOut * 2))
  readonly property string placeholder: {
    var p = String(prompt || "").replace(/[\s:]+$/, "")
    return p.length > 0 ? p : "Enter password"
  }
  readonly property alias field: passwordInput

  signal accepted()
  signal rejected()

  // A fresh prompt: empty, masked, focused; a retry's error flashes.
  function open() {
    done = false
    revealed = false
    passwordInput.text = ""
    if (String(error || "").length > 0) {
      errorFlash = true
      errorTimer.restart()
      shakeAnimation.restart()
    }
    Qt.callLater(refocus)
  }

  function refocus() {
    if (!done) passwordInput.forceActiveFocus()
  }

  function toggleReveal() {
    if (done) return
    revealed = !revealed
    refocus()
  }

  // What was typed, once; the field is emptied and masked.
  function takeText() {
    var text = passwordInput.text
    passwordInput.text = ""
    return text
  }

  function submit() {
    if (done) return
    done = true
    revealed = false
    accepted()
  }

  function cancel() {
    if (done) return
    done = true
    revealed = false
    passwordInput.text = ""
    rejected()
  }

  Timer {
    id: errorTimer
    interval: 1200
    repeat: false
    onTriggered: root.errorFlash = false
  }

  SequentialAnimation {
    id: shakeAnimation
    NumberAnimation { target: root; property: "shakeOffset"; to: -8; duration: 35; easing.type: Easing.OutQuad }
    NumberAnimation { target: root; property: "shakeOffset"; to: 8; duration: 50; easing.type: Easing.InOutQuad }
    NumberAnimation { target: root; property: "shakeOffset"; to: 0; duration: 55; easing.type: Easing.OutQuad }
  }

  Rectangle {
    anchors.fill: parent
    color: root.scrim
  }

  MouseArea {
    anchors.fill: parent
    onClicked: root.refocus()
  }

  BorderSurface {
    id: card
    width: root.cardWidth
    height: root.cardHeight
    radius: root.cornerRadius
    anchors.centerIn: parent
    anchors.horizontalCenterOffset: root.shakeOffset
    color: root.background
    borderSpec: root.borderSpec
    padding: root.contentMargin

    MouseArea { anchors.fill: parent; onClicked: root.refocus() }

    Row {
      anchors.fill: parent
      anchors.topMargin: card.contentTopInset
      anchors.rightMargin: card.contentRightInset
      anchors.bottomMargin: card.contentBottomInset
      anchors.leftMargin: card.contentLeftInset
      spacing: Style.space(14)

      Text {
        id: padlock
        objectName: "padlock"
        // Locked while masked, open while shown.
        text: root.revealed ? "" : ""
        color: root.errorFlash ? root.textError : root.accent
        font.family: root.fontFamily
        font.pixelSize: Style.font.iconLarge
        width: Style.space(26)
        height: root.fieldHeight
        horizontalAlignment: Text.AlignHCenter
        verticalAlignment: Text.AlignVCenter
        Accessible.role: Accessible.Button
        Accessible.name: root.revealed ? "Hide what is typed" : "Show what is typed"

        MouseArea {
          id: padlockArea
          objectName: "padlockArea"
          anchors.fill: parent
          cursorShape: Qt.PointingHandCursor
          onClicked: root.toggleReveal()
        }
      }

      Item {
        width: parent.width - Style.space(40)
        height: root.fieldHeight

        LineField {
          id: passwordInput
          objectName: "passwordInput"
          anchors.fill: parent
          framed: false
          fontFamily: root.fontFamily
          fontPixelSize: Style.font.iconLarge
          horizontalPadding: 0
          verticalPadding: 0
          password: !root.revealed
          readOnly: root.done
          submitsForm: false
          foreground: root.foreground
          accent: root.accent
          // Kept from input methods even while shown, like the panel's own
          // secret fields.
          inputMethodHints: Qt.ImhSensitiveData | Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase
          onAccepted: root.submit()
          Keys.onEscapePressed: function(event) {
            event.accepted = true
            root.cancel()
          }
        }

        Text {
          textFormat: Text.PlainText
          anchors.left: parent.left
          anchors.right: parent.right
          anchors.verticalCenter: parent.verticalCenter
          text: root.placeholder
          color: root.foreground
          opacity: 0.36
          font.family: root.fontFamily
          font.pixelSize: Style.font.iconLarge
          elide: Text.ElideRight
          visible: passwordInput.text.length === 0
        }

        Rectangle {
          width: Math.max(1, Style.space(2))
          height: Style.space(24)
          anchors.left: parent.left
          anchors.verticalCenter: parent.verticalCenter
          color: root.foreground
          visible: passwordInput.activeFocus && passwordInput.text.length === 0 && !root.done
        }

        MouseArea {
          anchors.fill: parent
          acceptedButtons: Qt.LeftButton
          onClicked: root.refocus()
        }
      }
    }
  }

  // The error of a retry, just above the card.
  Rectangle {
    id: errorPill
    objectName: "errorPill"
    visible: String(root.error || "").length > 0
    width: Math.min(errorText.implicitWidth + Style.space(24), root.width - Style.gapsOut * 2)
    height: Style.space(28)
    anchors.horizontalCenter: card.horizontalCenter
    anchors.bottom: card.top
    anchors.bottomMargin: Style.space(10)
    radius: root.cornerRadius
    color: root.background

    Text {
      id: errorText
      textFormat: Text.PlainText
      anchors.fill: parent
      anchors.leftMargin: Style.space(12)
      anchors.rightMargin: Style.space(12)
      text: root.error
      color: root.textError
      font.family: root.fontFamily
      font.pixelSize: Style.font.bodySmall
      horizontalAlignment: Text.AlignHCenter
      verticalAlignment: Text.AlignVCenter
      elide: Text.ElideRight
    }
  }

  // What is asked for, and for which account, as polkit shows its request.
  Rectangle {
    visible: String(root.description || "").length > 0
    width: Math.min(descriptionText.implicitWidth + Style.space(24), root.width - Style.gapsOut * 2)
    height: Style.space(28)
    anchors.horizontalCenter: card.horizontalCenter
    anchors.bottom: errorPill.visible ? errorPill.top : card.top
    anchors.bottomMargin: Style.space(10)
    radius: root.cornerRadius
    color: root.background

    Text {
      id: descriptionText
      textFormat: Text.PlainText
      anchors.fill: parent
      anchors.leftMargin: Style.space(12)
      anchors.rightMargin: Style.space(12)
      text: String(root.description || "").replace(/\s*\n\s*/g, " ")
      color: root.foreground
      font.family: root.fontFamily
      font.pixelSize: Style.font.bodySmall
      horizontalAlignment: Text.AlignHCenter
      verticalAlignment: Text.AlignVCenter
      elide: Text.ElideMiddle
    }
  }
}
