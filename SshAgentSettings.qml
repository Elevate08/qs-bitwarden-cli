import QtQuick
import qs.Commons
import qs.Ui
import "BitwardenModel.js" as Model

// The SSH agent settings sections: what the agent is doing, then whether the
// user's terminals reach it (routing). Neither gates the other. Stateless;
// reads the vault and calls back into it.
Column {
  id: section

  required property var panel
  // The vault this panel shows (Service.qml); `panel` is the view that draws it.
  required property var vault

  visible: vault.sshUiAvailable
  width: parent.width
  spacing: Style.space(6)

  Item { width: parent.width; height: Style.space(10) }

  SshSectionHeader {
    panel: section.panel
    text: "SSH AGENT STATUS"
  }

  Row {
    width: parent.width
    spacing: Style.space(8)

    Text {
      textFormat: Text.PlainText
      anchors.verticalCenter: parent.verticalCenter
      text: vault.sshAgentSetup.state === "enabled"
        ? (vault.sshAgentSetup.busy ? "󰔟" : "󰄬")
        : (vault.sshAgentSetup.state === "error" ? "󰀪" : "󰅘")
      color: vault.sshAgentSetup.state === "error"
        ? panel.urgent
        : (vault.sshAgentSetup.state === "enabled" && !vault.sshAgentSetup.busy ? Color.accent : panel.dim)
      font.family: panel.fontFamily
      font.pixelSize: Style.font.body
    }

    SshCaption {
      panel: section.panel
      width: parent.width - Style.space(30)
      text: vault.sshAgentSetup.message
      color: vault.sshAgentSetup.state === "error" ? panel.urgent : panel.dim
    }
  }

  // Which helper is running (shipped or local build).
  SshCaption {
    panel: section.panel
    visible: vault.sshAgentHelper.source !== ""
    text: "Using " + Model.sshAgentHelperSourceLabel(vault.sshAgentHelper.source)
      + (vault.sshAgentHelper.checksum === "match" ? " (checksum verified)" : "")
    color: vault.sshAgentHelper.source === "development" ? panel.urgent : panel.dim
  }

  // Why the feature is unavailable, if it is.
  SshCaption {
    panel: section.panel
    visible: vault.sshAgentEnabled && vault.sshAgentHelper.message !== ""
    text: vault.sshAgentHelper.message
    color: panel.urgent
  }

  // The helper's version, once it said hello.
  SshCaption {
    panel: section.panel
    visible: vault.sshAgentVersion !== ""
    text: "Helper version " + vault.sshAgentVersion
  }

  // The most likely reason a healthy agent goes unused. Judged by the routing
  // file; see sshAgentRoutingNotice().
  SshCaption {
    panel: section.panel
    visible: vault.sshAgentSetup.state === "enabled" && !vault.sshAgentSetup.busy
      && vault.sshRoutingNotice.text !== ""
    text: vault.sshRoutingNotice.text
    color: vault.sshRoutingNotice.urgent ? panel.urgent : panel.dim
  }

  Item { width: parent.width; height: Style.space(10) }

  SshSectionHeader {
    panel: section.panel
    text: "CLIENT ROUTING"
  }

  SshCaption {
    panel: section.panel
    text: vault.sshRouting.message
    color: vault.sshRouting.state === "matches" ? panel.dim : panel.fg
  }

  // Only the user's own terminal gives the authoritative answer.
  Text {
    textFormat: Text.PlainText
    width: parent.width
    text: "  " + vault.sshRouting.terminalCheck
    color: Color.accent
    font.family: panel.fontFamily
    font.pixelSize: Style.font.caption
    wrapMode: Text.WrapAnywhere
  }

  SshCaption {
    panel: section.panel
    text: vault.uwsmFragment.message
  }

  // Replacing the session's agent is confirmed, not done on the first click.
  SshCaption {
    panel: section.panel
    visible: vault.uwsmConfirmPending
    text: "This will make Bitwarden your session's SSH agent at the next login, replacing "
      + (vault.sshRouting.owner !== "" ? vault.sshRouting.owner : "the one you have now")
      + ". Continue?"
    color: panel.urgent
  }

  SshCaption {
    panel: section.panel
    visible: vault.uwsmFlash !== ""
    text: vault.uwsmFlash
    color: panel.fg
  }

  // A Flow, so whichever buttons the routing state shows wrap instead of
  // overflowing the panel.
  Flow {
    width: parent.width
    spacing: Style.space(8)

    Button {
      visible: !vault.uwsmConfirmPending && vault.uwsmFragment.state !== "managed"
      text: "Route SSH Clients Here"
      iconText: "󰌘"
      tooltipText: "Write " + Model.uwsmFragmentDisplayPath() + " so the next login points SSH clients at this agent"
      fontFamily: panel.fontFamily
      fontSize: Style.font.bodySmall
      enabled: !vault.uwsmBusy
      onClicked: vault.beginUwsmSetup()
    }

    Button {
      visible: vault.uwsmConfirmPending
      text: "Yes, Replace It"
      iconText: "󰄬"
      fontFamily: panel.fontFamily
      fontSize: Style.font.bodySmall
      enabled: !vault.uwsmBusy
      onClicked: vault.beginUwsmSetup()
    }

    Button {
      visible: vault.uwsmConfirmPending
      text: "Cancel"
      iconText: "󰅘"
      fontFamily: panel.fontFamily
      fontSize: Style.font.bodySmall
      onClicked: vault.cancelUwsmSetup()
    }

    Button {
      visible: !vault.uwsmConfirmPending && vault.uwsmFragment.removable
      text: "Remove Routing File"
      iconText: "󰩹"
      tooltipText: "Delete " + Model.uwsmFragmentDisplayPath()
      fontFamily: panel.fontFamily
      fontSize: Style.font.bodySmall
      enabled: !vault.uwsmBusy
      onClicked: vault.removeUwsmFragment()
    }
  }
  Item {
    visible: vault.sshGrants.length > 0
    width: parent.width
    height: visible ? Style.space(10) : 0
  }

  SshSectionHeader {
    panel: section.panel
    visible: vault.sshGrants.length > 0
    text: "ACTIVE APPROVALS"
  }

  // Live grants sign without prompting, so each is listed and revocable.
  Repeater {
    model: vault.sshGrants

    delegate: Row {
      required property var modelData
      width: parent.width
      spacing: Style.space(8)

      SshCaption {
        panel: section.panel
        width: parent.width - Style.space(110)
        text: modelData.keyName + "  ·  "
          + modelData.processName
          + (modelData.operationLabel ? "  ·  " + modelData.operationLabel : "")
          + (modelData.hostKey ? "  ·  " + modelData.hostKey : "")
          + "  ·  " + modelData.remainingLabel
      }

      Button {
        anchors.verticalCenter: parent.verticalCenter
        text: "Revoke"
        iconText: "󰩹"
        fontFamily: panel.fontFamily
        fontSize: Style.font.caption
        onClicked: vault.revokeSshGrant(modelData.grantId)
      }
    }
  }

  Button {
    visible: vault.sshGrants.length > 1
    text: "Revoke All Approvals"
    iconText: "󰩹"
    tooltipText: "Drop every live approval; the next signature asks again"
    fontFamily: panel.fontFamily
    fontSize: Style.font.bodySmall
    onClicked: vault.revokeAllSshGrants()
  }
}
