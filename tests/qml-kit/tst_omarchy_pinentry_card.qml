// pinentry/PinentryCard.qml, the plugin's pinentry prompt, with the
// shell kit's own BorderSurface: masked until the padlock is clicked, which
// gives the field its focus back; Enter submits and Escape cancels, and
// either, or opening again, masks it; a retry's error is shown above the
// field; what is typed is kept from input methods.
//
// The field is the panel's LineField, so a clipboard change cannot pull an
// offer into the prompt.
//
//   tests/qml-kit/run.sh tests/qml-kit/tst_omarchy_pinentry_card.qml
//
import QtQuick
import QtTest
import "../../pinentry"

TestCase {
  id: tc
  name: "OmarchyPinentryCard"
  when: windowShown
  width: 900; height: 600
  visible: true

  property int accepts: 0
  property int rejects: 0

  PinentryCard {
    id: card
    anchors.fill: parent
    description: "Unlock Bitwarden for you@example.com"
    prompt: "Master password:"
    onAccepted: tc.accepts++
    onRejected: tc.rejects++
  }

  function find(item, name) {
    if (!item) return null
    if (item.objectName === name) return item
    for (var i = 0; i < item.children.length; i++) {
      var hit = find(item.children[i], name)
      if (hit) return hit
    }
    return null
  }

  function init() {
    accepts = 0
    rejects = 0
    card.error = ""
    card.open()
    wait(0)
    tryCompare(card.field, "activeFocus", true)
  }

  function test_masked_and_focused_when_opened() {
    compare(card.field.echoMode, TextInput.Password, "the field starts in the clear")
    keyClick(Qt.Key_Q)
    compare(card.field.text, "q")
    verify(card.field.Window.activeFocusItem.text === "\u2022", "the field does not show a bullet")
    verify(card.field.activeFocus, "the field has no focus")
    compare(card.placeholder, "Master password")
  }

  function test_padlock_toggles_and_returns_focus() {
    var lock = find(card, "padlockArea")
    verify(lock !== null, "no padlock")
    keyClick(Qt.Key_A)
    mouseClick(lock)
    compare(card.field.echoMode, TextInput.Normal, "the padlock did not show the text")
    tryCompare(card.field, "activeFocus", true)
    keyClick(Qt.Key_B)
    compare(card.field.text, "ab", "typing after the padlock missed the field")
    mouseClick(lock)
    compare(card.field.echoMode, TextInput.Password, "the padlock did not hide it again")
    tryCompare(card.field, "activeFocus", true)
  }

  function test_enter_submits_and_masks() {
    card.toggleReveal()
    keyClick(Qt.Key_X)
    keyClick(Qt.Key_Y)
    keyClick(Qt.Key_Return)
    compare(accepts, 1, "Enter did not submit")
    compare(rejects, 0)
    compare(card.field.echoMode, TextInput.Password, "submitting left it shown")
    compare(card.takeText(), "xy", "the answer is not what was typed")
    compare(card.field.text, "", "the field kept the answer")
    keyClick(Qt.Key_Return)
    compare(accepts, 1, "a second Enter submitted again")
  }

  function test_keypad_enter_submits() {
    keyClick(Qt.Key_1)
    keyClick(Qt.Key_Enter)
    compare(accepts, 1)
  }

  function test_escape_cancels_and_masks() {
    card.toggleReveal()
    keyClick(Qt.Key_S)
    keyClick(Qt.Key_Escape)
    compare(rejects, 1, "Escape did not cancel")
    compare(accepts, 0)
    compare(card.field.text, "", "cancelling kept what was typed")
    compare(card.field.echoMode, TextInput.Password, "cancelling left it shown")
  }

  function test_reopening_masks_again() {
    card.toggleReveal()
    compare(card.field.echoMode, TextInput.Normal)
    card.open()
    compare(card.field.echoMode, TextInput.Password, "reopening left it shown")
    compare(card.field.text, "")
  }

  function test_error_is_shown_above_the_field() {
    var pill = find(card, "errorPill")
    verify(pill !== null, "no error pill")
    verify(!pill.visible, "an error shows without one")
    card.error = "Wrong master password"
    card.open()
    verify(pill.visible, "the retry's error is not shown")
    verify(card.errorFlash, "the retry does not flash")
    var input = card.field.mapToItem(card, 0, 0)
    var at = pill.mapToItem(card, 0, 0)
    verify(at.y + pill.height <= input.y, "the error is not above the field")
  }

  function test_input_methods_never_see_it() {
    card.toggleReveal()
    verify((card.field.inputMethodHints & Qt.ImhSensitiveData) !== 0, "not marked sensitive while shown")
    verify((card.field.inputMethodHints & Qt.ImhNoPredictiveText) !== 0, "prediction would learn it")
  }
}
