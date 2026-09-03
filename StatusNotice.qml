import QtQuick
import qs.Commons
import qs.Ui

// A transient panel-local notice. It anchors to its parent as an overlay and
// deliberately reports no height to the parent's content layout.
BorderSurface {
  id: root

  required property string statusMessage
  required property string errorMessage
  required property bool statusSuppressed
  required property color foreground
  required property color surfaceColor
  required property color accentColor
  required property color urgentColor
  required property string fontFamily

  readonly property bool showsError: root.errorMessage !== ""
  readonly property bool showsStatus: root.statusMessage !== "" && !root.statusSuppressed
  readonly property bool shown: showsError || showsStatus
  readonly property color tone: showsError ? root.urgentColor : root.accentColor

  // Optional recovery offered alongside an error. Empty means none.
  property string actionLabel: ""

  signal errorDismissed()
  signal actionRequested()

  anchors.horizontalCenter: parent.horizontalCenter
  anchors.bottom: parent.bottom
  anchors.bottomMargin: Style.space(10)
  width: Math.min(parent.width - Style.space(20), Style.space(390))
  implicitHeight: noticeRow.implicitHeight + Style.space(16)
  z: 20
  visible: opacity > 0
  enabled: shown
  opacity: shown ? 1 : 0
  color: root.surfaceColor
  radius: Style.cornerRadius
  borderSpec: Border.surfaceSpec("menu", "border", root.tone, 1)

  Accessible.role: Accessible.AlertMessage
  Accessible.name: (root.showsError ? "Needs attention: " : "Status: ") + noticeMessage.text
  Accessible.ignored: !root.shown

  Behavior on opacity {
    NumberAnimation { duration: 140; easing.type: Easing.OutQuad }
  }

  // Consume pointer presses on the floating surface so covered controls
  // cannot be activated through it.
  MouseArea {
    anchors.fill: parent
    acceptedButtons: Qt.AllButtons
  }

  Row {
    id: noticeRow
    anchors.fill: parent
    anchors.margins: Style.space(8)
    spacing: Style.space(8)

    Text {
      textFormat: Text.PlainText
      id: noticeIcon
      anchors.verticalCenter: parent.verticalCenter
      text: root.showsError ? "󰅚" : "󰋼"
      color: root.tone
      font.family: root.fontFamily
      font.pixelSize: Style.font.body
    }

    Column {
      anchors.verticalCenter: parent.verticalCenter
      width: parent.width - noticeIcon.implicitWidth - Style.space(8)
        - (dismissNoticeButton.visible
          ? dismissNoticeButton.implicitWidth + Style.space(8)
          : 0)
      spacing: Style.space(2)

      Text {
        textFormat: Text.PlainText
        width: parent.width
        text: root.showsError ? "NEEDS ATTENTION" : "STATUS"
        color: root.tone
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption
        font.bold: true
      }

      Text {
        textFormat: Text.PlainText
        id: noticeMessage
        width: parent.width
        text: root.showsError ? root.errorMessage : root.statusMessage
        color: root.foreground
        font.family: root.fontFamily
        font.pixelSize: Style.font.bodySmall
        wrapMode: Text.Wrap
      }
    }

    // An error the user can do something about carries the doing with it. A
    // failed save is the case this exists for: the message says the vault
    // refused it, and the button is the way back to what was typed.
    PanelActionButton {
      id: noticeActionButton
      visible: root.showsError && root.actionLabel !== ""
      anchors.verticalCenter: parent.verticalCenter
      iconText: "󰑌"
      tooltipText: root.actionLabel
      fontFamily: root.fontFamily
      onClicked: root.actionRequested()
    }

    PanelActionButton {
      id: dismissNoticeButton
      visible: root.showsError
      anchors.verticalCenter: parent.verticalCenter
      iconText: "󰅖"
      tooltipText: "Dismiss message"
      fontFamily: root.fontFamily
      onClicked: root.errorDismissed()
    }
  }
}
