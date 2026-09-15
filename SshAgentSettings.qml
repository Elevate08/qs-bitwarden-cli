import QtQuick
import qs.Commons
import qs.Ui
import "BitwardenModel.js" as Model

// The SSH agent's own settings sections, lifted out of Panel.qml so that file
// is not the only place this feature can be read.
//
// Two separate things, deliberately drawn apart. The top half is what the
// feature is doing; the bottom half is whether the user's terminals will
// reach it. Neither one gates the other. The approval screen lives with the
// other screens in Panel.qml, because that is what it is.
//
// `panel` is the Panel root: this section reads its vault and agent state and
// calls back into it for every action. Nothing here holds state of its own.
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

  // Which helper is running. A developer with a local build and a
  // user on a release see the same panel otherwise, and confusing
  // the two wastes an afternoon.
  SshCaption {
    panel: section.panel
    visible: vault.sshAgentHelper.source !== ""
    text: "Using " + Model.sshAgentHelperSourceLabel(vault.sshAgentHelper.source)
      + (vault.sshAgentHelper.checksum === "match" ? " (checksum verified)" : "")
    color: vault.sshAgentHelper.source === "development" ? panel.urgent : panel.dim
  }

  // Why the feature is unavailable, when it is. These are the
  // failures a real clone produces: a stale binary, a dropped file
  // mode, an LFS placeholder.
  SshCaption {
    panel: section.panel
    visible: vault.sshAgentEnabled && vault.sshAgentHelper.message !== ""
    text: vault.sshAgentHelper.message
    color: panel.urgent
  }

  // The helper's own version, once it has said hello. Non-secret,
  // and the quickest way to tell a stale bundled binary apart from
  // a working one.
  SshCaption {
    panel: section.panel
    visible: vault.sshAgentVersion !== ""
    text: "Helper version " + vault.sshAgentVersion
  }

  // Routing is the thing most likely to be missing when the agent looks
  // healthy and SSH still does not use it. Said here because this is the
  // block a user reads first, and decided by the routing file rather than by
  // this session's SSH_AUTH_SOCK -- see sshAgentRoutingNotice for why.
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

  // The check the user runs in the terminal they actually use --
  // which is the only place the answer is authoritative.
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

  // Replacing the session's primary agent is a real decision, so the
  // conflict is stated and confirmed rather than absorbed by the
  // first click.
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

  // A Flow, because which of these four are showing is decided by the routing
  // state: the idle pair and the confirming pair are each narrow enough, but
  // nothing in a Row enforces that, and a Row answers a set that is too wide by
  // laying the last button out past the panel edge rather than wrapping it.
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

  // Every live grant, with the process it belongs to and what is
  // left of it. A grant is a window in which signing happens with
  // no prompt, so it has to be visible and revocable while it runs.
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
