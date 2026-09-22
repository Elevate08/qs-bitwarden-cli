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
  // The vault this panel shows (Service.qml); `panel` is the view that draws it.
  required property var vault
  property bool active: vault.activeScreen === "sshApproval"

  // A signing decision should never open with an affirmative action focused.
  // Both the anchored panel and the centered popup can call this after their
  // window receives keyboard focus.
  function focusDefault() {
    if (screen.active && screen.visible) denyButton.forceActiveFocus()
  }

  visible: active && vault.sshPrompt !== null
  width: parent.width
  spacing: Style.space(12)

  PanelSeparator {
    visible: !screen.vault.sshAgentApprovalPopup
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

    Item { width: Math.max(0, parent.width - Style.space(vault.sshPendingCount > 1 ? 290 : 230)); height: 1 }

    Text {
      textFormat: Text.PlainText
      visible: vault.sshPendingCount > 1
      anchors.verticalCenter: parent.verticalCenter
      text: "1 of " + vault.sshPendingCount
      color: Color.accent
      font.family: panel.fontFamily
      font.pixelSize: Style.font.caption
      font.bold: true
    }

    Text {
      textFormat: Text.PlainText
      anchors.verticalCenter: parent.verticalCenter
      text: vault.sshPromptRemainingSec + "s left"
      color: vault.sshPromptRemainingSec <= 5 ? panel.urgent : panel.dim
      font.family: panel.fontFamily
      font.pixelSize: Style.font.caption
    }
  }

  // A forwarded request is called out rather than shown as ordinary
  // context, because the process named would not be the one using the
  // signature. The companion offers no grant for one.
  SshCaption {
    panel: screen.panel
    visible: vault.sshPrompt && vault.sshPrompt.forwardedWarning !== ""
    text: vault.sshPrompt ? vault.sshPrompt.forwardedWarning : ""
    color: panel.urgent
  }

  SshCaption {
    panel: screen.panel
    visible: vault.sshAgentLoadActive
    text: Model.sshAgentLoadingNote()
  }

  // What is being signed, as the companion read it from the request.
  // A grant covers this kind of signature and no other, so it is the
  // first thing worth checking.
  SshSectionHeader {
    panel: screen.panel
    visible: vault.sshPrompt && vault.sshPrompt.operationLabel !== ""
    text: "REQUEST"
  }

  Text {
    textFormat: Text.PlainText
    width: parent.width
    visible: vault.sshPrompt && vault.sshPrompt.operationLabel !== ""
    text: vault.sshPrompt ? vault.sshPrompt.operationLabel : ""
    color: panel.fg
    font.family: panel.fontFamily
    font.pixelSize: Style.font.body
    wrapMode: Text.WrapAnywhere
  }

  SshSectionHeader {
    panel: screen.panel
    text: "KEY"
  }

  Text {
    textFormat: Text.PlainText
    width: parent.width
    text: vault.sshPrompt ? vault.sshPrompt.keyName : ""
    color: panel.fg
    font.family: panel.fontFamily
    font.pixelSize: Style.font.body
    wrapMode: Text.WordWrap
  }

  // The fingerprint is the value worth checking, so it is shown whole
  // rather than elided.
  SshCaption {
    panel: screen.panel
    text: vault.sshPrompt ? vault.sshPrompt.fingerprint : ""
    wrapMode: Text.WrapAnywhere
  }

  SshSectionHeader {
    panel: screen.panel
    text: "REQUESTED BY"
  }

  Text {
    textFormat: Text.PlainText
    width: parent.width
    text: vault.sshPrompt
      ? vault.sshPrompt.processName
      : ""
    color: panel.fg
    font.family: panel.fontFamily
    font.pixelSize: Style.font.body
    wrapMode: Text.WordWrap
  }

  SshCaption {
    panel: screen.panel
    text: vault.sshPrompt ? vault.sshPrompt.processPath : ""
    wrapMode: Text.WrapAnywhere
  }

  SshCaption {
    panel: screen.panel
    text: vault.sshPrompt ? vault.sshPrompt.provenanceNote : ""
  }

  PanelSeparator {
    visible: !screen.vault.sshAgentApprovalPopup
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
      onClicked: vault.denySshRequest()
    }

    Button {
      visible: vault.sshPendingCount > 1
      text: "Deny all (" + vault.sshPendingCount + ")"
      iconText: "󰅙"
      fontFamily: panel.fontFamily
      fontSize: Style.font.bodySmall
      focusable: true
      onClicked: vault.denyAllSshRequests()
    }

    Button {
      text: "Approve once"
      iconText: "󰄬"
      fontFamily: panel.fontFamily
      fontSize: Style.font.bodySmall
      focusable: true
      onClicked: vault.approveSshRequest(0)
    }
  }

  Button {
    visible: vault.sshPrompt && vault.sshPrompt.grantOffered
    text: vault.sshPrompt ? vault.sshPrompt.grantLabel : ""
    iconText: "󰔟"
    tooltipText: "Sign further requests of this same kind from this same program with this key, without asking again, until the window expires"
    fontFamily: panel.fontFamily
    fontSize: Style.font.bodySmall
    focusable: true
    onClicked: vault.approveSshRequest(vault.sshPrompt ? vault.sshPrompt.grantSeconds : 0)
  }
}
