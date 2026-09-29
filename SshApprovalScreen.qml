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

  // The card appears while the user may still be typing or clicking in
  // another window: Tab then Space (or Enter) used to approve once, and
  // Shift+Tab then Enter opened a grant. So for armDelayMs after it appears,
  // after its request or the vault's status changes, and after the popup
  // takes keyboard focus, every key but Escape is dropped and the approve
  // tiles are disabled; then Deny takes focus. The same idea as Firefox's
  // security.dialog_enable_delay.
  readonly property int armDelayMs: 800
  property bool armed: false
  readonly property bool shown: active && visible

  // Starts the delay over and parks the keyboard on the guard.
  function rearm() {
    screen.armed = false
    if (!screen.shown) {
      armTimer.stop()
      return
    }
    armTimer.restart()
    keyGuard.forceActiveFocus()
  }

  // Never open with an affirmative action focused. Called by both the panel
  // and the popup once their window has keyboard focus.
  function focusDefault() {
    if (!screen.active || !screen.visible) return
    if (screen.armed) denyButton.forceActiveFocus()
    else keyGuard.forceActiveFocus()
  }

  onShownChanged: rearm()
  // A Loader may build the card already shown, when no change is signalled.
  Component.onCompleted: rearm()

  Connections {
    target: screen.vault
    function onSshPromptChanged() { screen.rearm() }
    function onStatusChanged() { screen.rearm() }
  }

  Timer {
    id: armTimer
    interval: screen.armDelayMs
    onTriggered: {
      screen.armed = true
      // Only if nothing else took the keyboard meanwhile (the panel's own
      // key dispatch, say): then Deny, never an approve tile.
      if (keyGuard.activeFocus) screen.focusDefault()
    }
  }

  // Holds the keyboard until the card is armed, and filters what the tiles
  // get afterwards (they forward here first): nothing but Escape before
  // arming, and no auto-repeated key after it, since a key held down from
  // before the card appeared is not an answer. Escape is never taken, so it
  // reaches the card's (or the panel's) deny.
  Item {
    id: keyGuard
    width: 0
    height: 0
    Keys.onPressed: function(event) {
      if (event.key === Qt.Key_Escape) return
      if (!screen.armed || event.isAutoRepeat) event.accepted = true
    }
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

  // Deny first, and no bare-Enter default: a stray key must not sign. Every
  // decision in one row, a column each, like the unlock methods.
  Row {
    id: decisionRow
    width: parent.width
    spacing: Style.space(6)

    readonly property bool denyAllOffered: vault.sshPendingCount > 1
    readonly property bool grantOffered: vault.sshPrompt !== null && vault.sshPrompt.grantOffered === true
    readonly property int count: 2 + (denyAllOffered ? 1 : 0) + (grantOffered ? 1 : 0)
    readonly property real tileWidth: (width - spacing * (count - 1)) / count

    ChoiceTile {
      id: denyButton
      panel: screen.panel
      width: decisionRow.tileWidth
      glyph: "󰅖"
      label: "Deny"
      tooltipText: "Refuse this request (Esc)"
      focusable: true
      Keys.forwardTo: [keyGuard]
      onClicked: vault.denySshRequest()
    }

    ChoiceTile {
      visible: decisionRow.denyAllOffered
      panel: screen.panel
      width: decisionRow.tileWidth
      glyph: "󰅙"
      label: "Deny all (" + vault.sshPendingCount + ")"
      tooltipText: "Refuse this request and every one waiting behind it"
      focusable: true
      Keys.forwardTo: [keyGuard]
      onClicked: vault.denyAllSshRequests()
    }

    ChoiceTile {
      panel: screen.panel
      width: decisionRow.tileWidth
      glyph: "󰄬"
      label: "Approve once"
      tooltipText: "Sign this one request"
      // Unreachable by keyboard or pointer until armed.
      enabled: screen.armed
      focusable: screen.armed
      opacity: screen.armed ? 1 : 0.45
      Keys.forwardTo: [keyGuard]
      onClicked: vault.approveSshRequest(0)
    }

    ChoiceTile {
      visible: decisionRow.grantOffered
      panel: screen.panel
      width: decisionRow.tileWidth
      glyph: "󰔟"
      label: vault.sshPrompt ? vault.sshPrompt.grantShortLabel : ""
      tooltipText: (vault.sshPrompt ? vault.sshPrompt.grantLabel + ": sign" : "Sign")
        + " further requests of this same kind from this same program with this key, without asking again, until the window expires"
      enabled: screen.armed
      focusable: screen.armed
      opacity: screen.armed ? 1 : 0.45
      Keys.forwardTo: [keyGuard]
      onClicked: vault.approveSshRequest(vault.sshPrompt ? vault.sshPrompt.grantSeconds : 0)
    }
  }
}
