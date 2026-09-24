import QtQuick
import qs.Commons
import qs.Ui
import "BitwardenModel.js" as Model

// SCREEN: SSH signing approval. Says what the companion verified (the
// requesting user) and marks everything else about the process as unverified
// context. Stateless: draws the pending request and calls back.
Column {
  id: screen

  required property var panel
  // The vault this panel shows (Service.qml); `panel` is the view that draws it.
  required property var vault
  property bool active: vault.activeScreen === "sshApproval"

  // Never open with an affirmative action focused. Called by both the panel
  // and the popup once their window has keyboard focus.
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

  // Forwarded requests are flagged: the named process is not the one that
  // will use the signature, and no grant is offered.
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

  // What is being signed; a grant covers only this kind of signature.
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

  // A login's server, as the client bound it; a login grant covers only it.
  SshCaption {
    panel: screen.panel
    visible: vault.sshPrompt && vault.sshPrompt.destinationLabel !== ""
    text: vault.sshPrompt ? vault.sshPrompt.destinationLabel : ""
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

  // Shown whole, not elided: this is the value to check.
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

  // Deny first, and no bare-Enter default: a stray key must not sign.
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
