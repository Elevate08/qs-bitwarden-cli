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

  // The bar's foreground and font family, not the global theme's -- the same
  // values the rest of the panel draws with. PanelSectionHeader and Text both
  // default to the globals, so every text element here states them.
  component SshSectionHeader: PanelSectionHeader {
    textFormat: Text.PlainText
    foreground: section.panel.fg
    fontFamily: section.panel.fontFamily
  }

  component SshCaption: Text {
    textFormat: Text.PlainText
    width: parent ? parent.width : 0
    color: section.panel.dim
    font.family: section.panel.fontFamily
    font.pixelSize: Style.font.caption
    wrapMode: Text.WordWrap
  }

  visible: panel.sshUiAvailable
  width: parent.width
  spacing: Style.space(6)

  Item { width: parent.width; height: Style.space(10) }

  SshSectionHeader {
    text: "SSH AGENT STATUS"
  }

  Row {
    width: parent.width
    spacing: Style.space(8)

    Text {
      textFormat: Text.PlainText
      anchors.verticalCenter: parent.verticalCenter
      text: panel.sshAgentSetup.state === "enabled"
        ? (panel.sshAgentSetup.busy ? "󰔟" : "󰄬")
        : (panel.sshAgentSetup.state === "error" ? "󰀪" : "󰅘")
      color: panel.sshAgentSetup.state === "error"
        ? panel.urgent
        : (panel.sshAgentSetup.state === "enabled" && !panel.sshAgentSetup.busy ? Color.accent : panel.dim)
      font.family: panel.fontFamily
      font.pixelSize: Style.font.body
    }

    SshCaption {
      width: parent.width - Style.space(30)
      text: panel.sshAgentSetup.message
      color: panel.sshAgentSetup.state === "error" ? panel.urgent : panel.dim
    }
  }

  // Which helper is running. A developer with a local build and a
  // user on a release see the same panel otherwise, and confusing
  // the two wastes an afternoon.
  SshCaption {
    visible: panel.sshAgentHelper.source !== ""
    text: "Using " + Model.sshAgentHelperSourceLabel(panel.sshAgentHelper.source)
      + (panel.sshAgentHelper.checksum === "match" ? " (checksum verified)" : "")
    color: panel.sshAgentHelper.source === "development" ? panel.urgent : panel.dim
  }

  // Why the feature is unavailable, when it is. These are the
  // failures a real clone produces: a stale binary, a dropped file
  // mode, an LFS placeholder.
  SshCaption {
    visible: panel.sshAgentEnabled && panel.sshAgentHelper.message !== ""
    text: panel.sshAgentHelper.message
    color: panel.urgent
  }

  // The helper's own version, once it has said hello. Non-secret,
  // and the quickest way to tell a stale bundled binary apart from
  // a working one.
  SshCaption {
    visible: panel.sshAgentVersion !== ""
    text: "Helper version " + panel.sshAgentVersion
  }

  Item {
    visible: panel.sshGrants.length > 0
    width: parent.width
    height: visible ? Style.space(10) : 0
  }

  SshSectionHeader {
    visible: panel.sshGrants.length > 0
    text: "ACTIVE APPROVALS"
  }

  // Every live grant, with the process it belongs to and what is
  // left of it. A grant is a window in which signing happens with
  // no prompt, so it has to be visible and revocable while it runs.
  Repeater {
    model: panel.sshGrants

    delegate: Row {
      required property var modelData
      width: parent.width
      spacing: Style.space(8)

      SshCaption {
        width: parent.width - Style.space(110)
        text: modelData.keyName + "  ·  "
          + modelData.processName + " (pid " + modelData.pid + ")"
          + "  ·  " + modelData.remainingLabel
      }

      Button {
        anchors.verticalCenter: parent.verticalCenter
        text: "Revoke"
        iconText: "󰩹"
        fontFamily: panel.fontFamily
        fontSize: Style.font.caption
        onClicked: panel.revokeSshGrant(modelData.grantId)
      }
    }
  }

  Button {
    visible: panel.sshGrants.length > 1
    text: "Revoke All Approvals"
    iconText: "󰩹"
    tooltipText: "Drop every live approval; the next signature asks again"
    fontFamily: panel.fontFamily
    fontSize: Style.font.bodySmall
    onClicked: panel.revokeAllSshGrants()
  }

  Item { width: parent.width; height: Style.space(10) }

  SshSectionHeader {
    text: "CLIENT ROUTING"
  }

  SshCaption {
    text: panel.sshRouting.message
    color: panel.sshRouting.state === "matches" ? panel.dim : panel.fg
  }

  // The check the user runs in the terminal they actually use --
  // which is the only place the answer is authoritative.
  Text {
    textFormat: Text.PlainText
    width: parent.width
    text: "  " + panel.sshRouting.terminalCheck
    color: Color.accent
    font.family: panel.fontFamily
    font.pixelSize: Style.font.caption
    wrapMode: Text.WrapAnywhere
  }

  SshCaption {
    text: panel.uwsmFragment.message
  }

  // Replacing the session's primary agent is a real decision, so the
  // conflict is stated and confirmed rather than absorbed by the
  // first click.
  SshCaption {
    visible: panel.uwsmConfirmPending
    text: "This will make Bitwarden your session's SSH agent at the next login, replacing "
      + (panel.sshRouting.owner !== "" ? panel.sshRouting.owner : "the one you have now")
      + ". Continue?"
    color: panel.urgent
  }

  SshCaption {
    visible: panel.uwsmFlash !== ""
    text: panel.uwsmFlash
    color: panel.fg
  }

  Row {
    width: parent.width
    spacing: Style.space(8)

    Button {
      visible: !panel.uwsmConfirmPending && panel.uwsmFragment.state !== "managed"
      text: "Route SSH Clients Here"
      iconText: "󰌘"
      tooltipText: "Write " + Model.uwsmFragmentDisplayPath() + " so the next login points SSH clients at this agent"
      fontFamily: panel.fontFamily
      fontSize: Style.font.bodySmall
      enabled: !panel.uwsmBusy
      onClicked: panel.beginUwsmSetup()
    }

    Button {
      visible: panel.uwsmConfirmPending
      text: "Yes, Replace It"
      iconText: "󰄬"
      fontFamily: panel.fontFamily
      fontSize: Style.font.bodySmall
      enabled: !panel.uwsmBusy
      onClicked: panel.beginUwsmSetup()
    }

    Button {
      visible: panel.uwsmConfirmPending
      text: "Cancel"
      iconText: "󰅘"
      fontFamily: panel.fontFamily
      fontSize: Style.font.bodySmall
      onClicked: panel.cancelUwsmSetup()
    }

    Button {
      visible: !panel.uwsmConfirmPending && panel.uwsmFragment.removable
      text: "Remove Routing File"
      iconText: "󰩹"
      tooltipText: "Delete " + Model.uwsmFragmentDisplayPath()
      fontFamily: panel.fontFamily
      fontSize: Style.font.bodySmall
      enabled: !panel.uwsmBusy
      onClicked: panel.removeUwsmFragment()
    }
  }
}
