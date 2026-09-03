import QtQuick
import qs.Commons
import qs.Ui
import "BitwardenModel.js" as Model

// SCREEN: SSH signing approval.
//
// The one place a signature is authorised. It states what the companion
// verified -- the requesting user -- and is explicit that everything else
// about the process is context rather than identity.
//
// `panel` is the Panel root. This screen holds no state: it draws the pending
// request and calls back for the answer.
Column {
  id: screen

  required property var panel
  property bool active: panel.activeScreen === "sshApproval"

  // A signing decision should never open with an affirmative action focused.
  // Both the anchored panel and the centered popup can call this after their
  // window receives keyboard focus.
  function focusDefault() {
    if (screen.active && screen.visible) denyButton.forceActiveFocus()
  }

  // The bar's foreground and font family rather than the global theme's, the
  // same as every other text element in this panel. Text defaults to AutoText,
  // so the format is stated even where the string is constant today.
  component SshSectionHeader: PanelSectionHeader {
    textFormat: Text.PlainText
    foreground: screen.panel.fg
    fontFamily: screen.panel.fontFamily
  }

  component SshCaption: Text {
    textFormat: Text.PlainText
    width: parent ? parent.width : 0
    color: screen.panel.dim
    font.family: screen.panel.fontFamily
    font.pixelSize: Style.font.caption
    wrapMode: Text.WordWrap
  }

  visible: active && panel.sshPrompt !== null
  width: parent.width
  spacing: Style.space(12)

  PanelSeparator {
    visible: !screen.panel.sshAgentApprovalPopup
    width: parent.width
  }

  Row {
    width: parent.width
    spacing: Style.space(8)

    Text {
      textFormat: Text.PlainText
      anchors.verticalCenter: parent.verticalCenter
      text: "󰌆"
      color: Color.accent
      font.family: panel.fontFamily
      font.pixelSize: Style.font.body
    }

    Text {
      textFormat: Text.PlainText
      anchors.verticalCenter: parent.verticalCenter
      text: "SSH signing request"
      color: panel.fg
      font.family: panel.fontFamily
      font.pixelSize: Style.font.body
    }

    Item { width: Math.max(0, parent.width - Style.space(230)); height: 1 }

    Text {
      textFormat: Text.PlainText
      anchors.verticalCenter: parent.verticalCenter
      text: panel.sshPromptRemainingSec + "s left"
      color: panel.sshPromptRemainingSec <= 5 ? panel.urgent : panel.dim
      font.family: panel.fontFamily
      font.pixelSize: Style.font.caption
    }
  }

  // Forwarding is rejected in v1. If one ever reaches here it is
  // called out rather than shown as ordinary context, because the
  // process named would not be the one using the signature.
  SshCaption {
    visible: panel.sshPrompt && panel.sshPrompt.forwardedWarning !== ""
    text: panel.sshPrompt ? panel.sshPrompt.forwardedWarning : ""
    color: panel.urgent
  }

  SshCaption {
    visible: panel.sshAgentLoadActive
    text: Model.sshAgentLoadingNote()
  }

  SshSectionHeader {
    text: "KEY"
  }

  Text {
    textFormat: Text.PlainText
    width: parent.width
    text: panel.sshPrompt ? panel.sshPrompt.keyName : ""
    color: panel.fg
    font.family: panel.fontFamily
    font.pixelSize: Style.font.body
    wrapMode: Text.WordWrap
  }

  // The fingerprint is the value worth checking, so it is shown whole
  // rather than elided.
  SshCaption {
    text: panel.sshPrompt ? panel.sshPrompt.fingerprint : ""
    wrapMode: Text.WrapAnywhere
  }

  SshSectionHeader {
    text: "REQUESTED BY"
  }

  Text {
    textFormat: Text.PlainText
    width: parent.width
    text: panel.sshPrompt
      ? panel.sshPrompt.processName
      : ""
    color: panel.fg
    font.family: panel.fontFamily
    font.pixelSize: Style.font.body
    wrapMode: Text.WordWrap
  }

  SshCaption {
    text: panel.sshPrompt ? panel.sshPrompt.processPath : ""
    wrapMode: Text.WrapAnywhere
  }

  SshCaption {
    text: panel.sshPrompt ? panel.sshPrompt.provenanceNote : ""
  }

  PanelSeparator {
    visible: !screen.panel.sshAgentApprovalPopup
    width: parent.width
  }

  // Deny leads, and nothing is activated by a bare Enter: a stray
  // keypress must not be able to sign.
  Row {
    width: parent.width
    spacing: Style.space(8)

    Button {
      id: denyButton
      text: "Deny (Esc)"
      iconText: "󰅘"
      fontFamily: panel.fontFamily
      fontSize: Style.font.bodySmall
      focusable: true
      onClicked: panel.denySshRequest()
    }

    Button {
      text: "Approve once"
      iconText: "󰄬"
      fontFamily: panel.fontFamily
      fontSize: Style.font.bodySmall
      focusable: true
      onClicked: panel.approveSshRequest(0)
    }
  }

  Button {
    visible: panel.sshPrompt && panel.sshPrompt.grantOffered
    text: panel.sshPrompt ? panel.sshPrompt.grantLabel : ""
    iconText: "󰔟"
    tooltipText: "Sign further requests from this same program with this key, without asking again, until the window expires"
    fontFamily: panel.fontFamily
    fontSize: Style.font.bodySmall
    focusable: true
    onClicked: panel.approveSshRequest(panel.sshPrompt ? panel.sshPrompt.grantSeconds : 0)
  }
}
