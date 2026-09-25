// The master password re-prompt question (RepromptConfirm.qml): shown while
// the vault holds a protected action, masked, Enter hands the password to the
// vault and Escape drops the action, and the typed password never stays in
// the field.
//
//   tests/qml-kit/run.sh tests/qml-kit/tst_reprompt_confirm.qml
//
import QtQuick
import QtTest
import "../.."

TestCase {
  id: tc
  name: "RepromptConfirm"
  when: windowShown
  width: 480; height: 600
  visible: true

  property var calls: []

  QtObject {
    id: fakePanel
    property string fontFamily: "monospace"
    property color fg: "white"
    property color dim: "gray"
    property color urgent: "red"
  }

  QtObject {
    id: fakeVault
    property bool repromptPending: false
    property string repromptItemName: ""
    property string repromptError: ""
    function submitReprompt(password) { tc.calls.push("submit(" + password + ")") }
    function cancelReprompt() { tc.calls.push("cancel"); repromptPending = false }
    function restoreScreenFocus() { tc.calls.push("restoreFocus") }
  }

  // What the panel's own Escape would do, to prove the question takes it.
  Item {
    id: host
    width: 460
    height: 560
    Keys.onEscapePressed: tc.calls.push("panelEscape")

    RepromptConfirm {
      id: confirm
      anchors.fill: parent
      panel: fakePanel
      vault: fakeVault
    }
  }

  function field() { return confirm.Window.activeFocusItem }

  function init() {
    tc.calls = []
    fakeVault.repromptError = ""
    fakeVault.repromptItemName = "Bank"
    fakeVault.repromptPending = true
    tryVerify(function() { return field() !== null && field().echoMode === TextInput.Password },
      1000, "the masked password field did not take focus")
    tc.calls = []
  }

  function cleanup() {
    fakeVault.repromptPending = false
    wait(0)
  }

  function test_hidden_until_asked() {
    fakeVault.repromptPending = false
    verify(!confirm.visible, "the question shows with nothing pending")
    fakeVault.repromptPending = true
    verify(confirm.visible, "the question does not show while an action waits")
  }

  function test_the_field_is_masked_and_kept_from_input_methods() {
    var f = field()
    compare(f.echoMode, TextInput.Password)
    verify((f.inputMethodHints & Qt.ImhSensitiveData) !== 0, "input methods would see the password")
    verify((f.inputMethodHints & Qt.ImhNoPredictiveText) !== 0, "prediction would learn the password")
  }

  function test_enter_hands_the_password_over_and_clears_the_field() {
    keyClick(Qt.Key_P); keyClick(Qt.Key_W)
    keyClick(Qt.Key_Return)
    compare(tc.calls.join(","), "submit(pw)")
    compare(field().text, "", "the password stayed in the field after it was submitted")
  }

  function test_enter_with_nothing_typed_submits_nothing() {
    keyClick(Qt.Key_Return)
    compare(tc.calls.join(","), "")
  }

  function test_escape_cancels_and_never_reaches_the_panel() {
    keyClick(Qt.Key_S)
    keyClick(Qt.Key_Escape)
    verify(tc.calls.indexOf("cancel") !== -1, "Escape did not cancel the protected action")
    verify(tc.calls.indexOf("panelEscape") === -1, "Escape also reached the panel, which would leave the screen")
    verify(!confirm.visible)
  }

  function test_a_wrong_password_is_reported() {
    fakeVault.repromptError = "Incorrect master password"
    var shown = false
    var rows = [confirm]
    while (rows.length > 0) {
      var item = rows.shift()
      if (item.text === "Incorrect master password" && item.visible) shown = true
      for (var i = 0; i < item.children.length; i++) rows.push(item.children[i])
    }
    verify(shown, "the vault's error is not shown")
  }

  function test_closing_hands_focus_back_to_the_screen() {
    fakeVault.repromptPending = false
    verify(tc.calls.indexOf("restoreFocus") !== -1, "focus was left on a hidden field")
  }
}
