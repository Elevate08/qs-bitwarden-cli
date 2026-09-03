import QtQuick
import Quickshell
import Quickshell.Wayland
import qs.Commons
import qs.Ui

// A transient, centered SSH authorization surface. The full-screen layer
// window supplies the scrim, outside-click denial, and keyboard focus; only
// the compact card is visible. It is tied to the bar widget's screen but not
// positioned relative to the bar, so the plugin otherwise stays out of sight.
PanelWindow {
  id: popup

  required property var panel
  required property Item anchorItem

  readonly property bool open: panel.sshAgentApprovalPopup && (panel.sshPrompt !== null || panel.sshUnlockRequest !== null)
  property bool focusPrimed: false
  readonly property var anchorWindow: anchorItem ? anchorItem.QsWindow.window : null
  readonly property int cardWidth: Math.max(1, Math.min(Style.space(460), width - Style.gapsOut * 2))
  readonly property int cardHeight: Math.max(1, Math.min(
    content.implicitHeight + card.contentTopInset + card.contentBottomInset,
    height - Style.gapsOut * 2))

  function beginFocusPrime() {
    if (open && backingWindowVisible) focusPrimeTimer.restart()
  }

  function refocus() {
    if (!open) return
    Qt.callLater(function() {
      if (!popup.open) return
      if (popup.panel.sshPrompt) approvalScreen.focusDefault()
      else unlockScreen.focusDefault()
    })
  }

  screen: anchorItem && anchorItem.QsWindow.window ? anchorItem.QsWindow.window.screen : null
  visible: open
  color: "transparent"
  exclusionMode: ExclusionMode.Ignore

  WlrLayershell.namespace: "qs-bitwarden-ssh-approval"
  WlrLayershell.layer: WlrLayer.Overlay
  // Prime focus briefly so keyboard-summoned requests reliably receive it,
  // then settle to OnDemand so another monitor is not pointer-blocked.
  WlrLayershell.keyboardFocus: open
    ? (focusPrimed ? WlrKeyboardFocus.OnDemand : WlrKeyboardFocus.Exclusive)
    : WlrKeyboardFocus.None

  anchors {
    top: true
    bottom: true
    left: true
    right: true
  }

  onBackingWindowVisibleChanged: beginFocusPrime()
  onOpenChanged: {
    if (open) {
      focusPrimed = false
      beginFocusPrime()
      refocus()
    } else {
      focusPrimeTimer.stop()
      focusPrimed = false
    }
  }

  Connections {
    target: popup.panel
    function onSshPromptChanged() { popup.refocus() }
    function onSshUnlockRequestChanged() { popup.refocus() }
    function onStatusChanged() { popup.refocus() }
  }

  Timer {
    id: focusPrimeTimer
    interval: 75
    repeat: false
    onTriggered: {
      popup.focusPrimed = true
      popup.refocus()
    }
  }

  Rectangle {
    anchors.fill: parent
    color: Color.menu.scrim
  }

  MouseArea {
    anchors.fill: parent
    onClicked: popup.panel.denySshRequest()
  }

  BorderSurface {
    id: card
    width: popup.cardWidth
    height: popup.cardHeight
    anchors.centerIn: parent
    radius: Style.cornerRadius
    color: Color.popups.background
    borderSpec: Border.surfaceSpec("popups", "border", Color.popups.border,
      Math.max(1, Style.space(2)))
    padding: Style.spacing.panelPadding

    // Swallow clicks on unused card space; only a click outside the card is a
    // denial. Interactive children declared below remain above this catcher.
    MouseArea { anchors.fill: parent; onClicked: {} }

    Item {
      id: keyScope
      anchors.fill: parent
      anchors.topMargin: card.contentTopInset
      anchors.rightMargin: card.contentRightInset
      anchors.bottomMargin: card.contentBottomInset
      anchors.leftMargin: card.contentLeftInset
      focus: popup.open

      Keys.priority: Keys.BeforeItem
      Keys.onPressed: function(event) {
        if (event.key === Qt.Key_Escape && !(event.modifiers & ~Qt.KeypadModifier)) {
          popup.panel.denySshRequest()
          event.accepted = true
        }
      }

      Flickable {
        id: scroller
        anchors.fill: parent
        contentWidth: width
        contentHeight: content.implicitHeight
        clip: true
        flickableDirection: Flickable.VerticalFlick
        boundsBehavior: Flickable.StopAtBounds
        interactive: contentHeight > height

        Column {
          id: content
          width: scroller.width

          SshUnlockScreen {
            id: unlockScreen
            panel: popup.panel
            active: popup.open && popup.panel.sshPrompt === null
          }

          SshApprovalScreen {
            id: approvalScreen
            panel: popup.panel
            active: popup.open && popup.panel.sshPrompt !== null
          }
        }
      }
    }
  }
}
