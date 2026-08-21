// Escape must cancel out of a form, and the panel's key wiring makes that
// non-obvious enough to be worth pinning down. Two separate traps live here.
//
// 1. PanelKeyCatcher goes `blocked` on every screen built around a text field
//    -- the item form, PIN, fingerprint, the Send composer -- and a blocked
//    catcher drops ALL keys, Escape included. So Escape is dispatched from the
//    shortcut interceptor, which the catcher reaches through Keys.forwardTo
//    before its own handler and regardless of `blocked`.
//
// 2. Qt does NOT clear active focus when an item is hidden. The search field
//    keeps focus behind the item form, and its own Keys.onEscapePressed used
//    to fire from back there and close the whole panel. Two things stop that:
//    the handler ignores Escape unless the search box is the current screen,
//    and focus is re-homed whenever the screen changes.
//
// Needs Qt, which any machine running the plugin already has:
//
//   QT_QPA_PLATFORM=offscreen qmltestrunner -input tests/qml
//
import QtQuick
import QtQuick.Controls
import QtTest
// Namespaced so the kit's own TextField (which needs the shell's import path)
// does not shadow the plain QtQuick.Controls one used below.
import "file:/usr/share/omarchy/shell/Ui" as OmarchyUi

TestCase {
  id: tc
  name: "EscapeRouting"
  when: windowShown
  width: 300; height: 200
  visible: true

  property string screenName: "main"
  property int interceptorEscapes: 0
  property int catcherCloses: 0
  property int panelCloses: 0
  property string trail: ""

  // Stands in for Panel.qml's handleEscape().
  function handleEscape() {
    tc.interceptorEscapes++
    tc.trail += "dispatch(" + tc.screenName + ") "
    if (tc.screenName === "edit") tc.screenName = "main"
    else tc.panelCloses++
  }

  onScreenNameChanged: restoreScreenFocus()

  function restoreScreenFocus() {
    if (tc.screenName === "main") searchField.forceActiveFocus()
    else if (tc.screenName === "edit") formField.forceActiveFocus()
  }

  // Stands in for Panel.qml's shortcutInterceptor.
  Item {
    id: interceptor
    Keys.onPressed: function(event) {
      if (event.key === Qt.Key_Escape && !(event.modifiers & ~Qt.KeypadModifier)) {
        tc.handleEscape()
        event.accepted = true
      }
    }
  }

  OmarchyUi.PanelKeyCatcher {
    id: catcher
    anchors.fill: parent
    Keys.forwardTo: [interceptor]
    blocked: searchField.activeFocus || tc.screenName === "edit"
    onCloseRequested: tc.catcherCloses++

    Column {
      anchors.fill: parent

      Column {
        visible: tc.screenName === "main"
        TextField {
          id: searchField
          Keys.onEscapePressed: function(event) {
            tc.trail += "searchField "
            if (tc.screenName !== "main") { event.accepted = false; return }
            if (text) text = ""
            else tc.panelCloses++
          }
        }
      }

      Column {
        visible: tc.screenName === "edit"
        TextField { id: formField }
      }
    }
  }

  function init() {
    tc.interceptorEscapes = 0
    tc.catcherCloses = 0
    tc.panelCloses = 0
    tc.trail = ""
  }

  // The bug behind "Escape does nothing on the item form": on that screen the
  // catcher is blocked and a field holds focus.
  function test_1_escape_survives_a_blocked_catcher() {
    tc.screenName = "edit"
    formField.forceActiveFocus()
    verify(formField.activeFocus, "the form field should hold focus")
    keyClick(Qt.Key_Escape)
    compare(tc.interceptorEscapes, 1, "Escape must reach the dispatch through a blocked catcher")
    compare(tc.catcherCloses, 0, "a blocked catcher never fires closeRequested -- that was the bug")
    compare(tc.panelCloses, 0, "and it must not close the panel")
  }

  // The bug behind "Escape closes the whole panel": hiding the main screen
  // does not take focus off the search box, so it kept answering Escape.
  function test_2_hidden_search_field_does_not_answer_escape() {
    tc.screenName = "edit"
    wait(0)
    // Force the stale-owner state directly: focus the hidden search field
    // while the form is showing. Re-homing normally prevents this, so this
    // isolates the handler's own guard rather than leaning on that.
    searchField.forceActiveFocus()
    verify(searchField.activeFocus, "the hidden search field holds focus")
    verify(!searchField.visible, "and it is hidden behind the form")

    keyClick(Qt.Key_Escape)
    compare(tc.panelCloses, 0, "a hidden search field must not close the panel: " + tc.trail)
    compare(tc.screenName, "main", "Escape should cancel the edit instead")
  }

  // Re-homing focus on a screen change is what stops the stale owner
  // accumulating in the first place.
  function test_3_focus_follows_the_screen() {
    tc.screenName = "main"
    searchField.forceActiveFocus()
    tc.screenName = "edit"
    wait(0)
    verify(formField.activeFocus, "the form field should take focus when the form opens")
    verify(!searchField.activeFocus, "the hidden search field should not still hold it")
  }

  // Blocking exists so letters are typed rather than read as shortcuts;
  // intercepting Escape must not cost that.
  function test_4_typing_still_reaches_the_field() {
    tc.screenName = "edit"
    formField.text = ""
    formField.forceActiveFocus()
    keyClick(Qt.Key_J)
    compare(formField.text, "j", "letters must still land in the field")
    compare(tc.interceptorEscapes, 0, "no stray Escape")
  }

  // On unblocked screens both handlers are live; the interceptor accepting the
  // event is what keeps the dispatch from running twice.
  function test_5_escape_is_dispatched_once_when_unblocked() {
    tc.screenName = "settings"
    catcher.forceActiveFocus()
    keyClick(Qt.Key_Escape)
    compare(tc.interceptorEscapes, 1, "interceptor handles Escape")
    compare(tc.catcherCloses, 0, "catcher must not fire once the interceptor accepted")
  }
}
