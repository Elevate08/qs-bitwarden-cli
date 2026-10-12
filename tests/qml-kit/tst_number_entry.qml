// NumberEntry: typed entry without an editable TextInput. Digits and Return
// commit once, clamped; Up/Down step; a programmatic value change is silent;
// paste and non-digits are ignored; Return and Tab insert nothing; focus loss
// commits. The no-editable-input rule is pinned in tests/number-entry.test.js.
//
//   tests/qml-kit/run.sh tests/qml-kit/tst_number_entry.qml
import QtQuick
import QtQuick.Controls
import QtTest
import "../.."

TestCase {
  id: tc
  name: "NumberEntry"
  when: windowShown
  width: 300
  height: 240
  visible: true

  QtObject {
    id: store
    property int value: 5
  }

  Column {
    spacing: 8
    NumberEntry {
      id: num
      value: store.value
      from: 0
      to: 9
      onModified: function(v) { store.value = v }
    }
    NumberEntry {
      id: signedNum
      value: 0
      from: -20
      to: 20
    }
    TextInput { id: other; readOnly: true; activeFocusOnTab: true; width: 20; height: 20 }
  }

  SignalSpy { id: mods; target: num; signalName: "modified" }
  SignalSpy { id: signedMods; target: signedNum; signalName: "modified" }

  function edit(entry) { return entry.field.contentItem }

  function focusEdit(entry) {
    edit(entry).forceActiveFocus()
    verify(edit(entry).activeFocus)
    edit(entry).selectAll()
  }

  function init() {
    // Leaving a field commits what was typed in it; start each test clean.
    other.forceActiveFocus()
    store.value = 5
    mods.clear()
    signedMods.clear()
    tryCompare(edit(num), "text", "5")
  }

  function test_type_and_return_commits_clamped_once() {
    focusEdit(num)
    keyClick(Qt.Key_4)
    keyClick(Qt.Key_2)
    compare(mods.count, 0)
    keyClick(Qt.Key_Return)
    compare(mods.count, 1)
    compare(mods.signalArguments[0][0], 9)
    compare(store.value, 9)
    compare(edit(num).text, "9")
    compare(edit(num).text.indexOf("\n"), -1)
  }

  function test_enter_key_commits() {
    focusEdit(num)
    keyClick(Qt.Key_7)
    keyClick(Qt.Key_Enter)
    compare(mods.count, 1)
    compare(store.value, 7)
  }

  function test_commit_of_same_value_is_silent() {
    focusEdit(num)
    keyClick(Qt.Key_5)
    keyClick(Qt.Key_Return)
    compare(mods.count, 0)
    compare(edit(num).text, "5")
  }

  function test_up_down_step_and_emit() {
    focusEdit(num)
    keyClick(Qt.Key_Up)
    compare(mods.count, 1)
    compare(store.value, 6)
    keyClick(Qt.Key_Down)
    keyClick(Qt.Key_Down)
    compare(mods.count, 3)
    compare(store.value, 4)
    compare(edit(num).text, "4")
  }

  function test_programmatic_value_change_does_not_emit() {
    store.value = 8
    compare(mods.count, 0)
    compare(edit(num).text, "8")
    compare(num.field.value, 8)
  }

  function test_paste_is_ignored() {
    focusEdit(num)
    keyClick(Qt.Key_V, Qt.ControlModifier)
    compare(edit(num).text, "5")
    keySequence(StandardKey.Paste)
    compare(edit(num).text, "5")
    compare(mods.count, 0)
  }

  function test_non_digits_are_ignored() {
    focusEdit(num)
    keyClick(Qt.Key_A)
    keyClick(Qt.Key_Minus)
    keyClick(Qt.Key_Space)
    keyClick(Qt.Key_Period)
    compare(edit(num).text, "5")
    keyClick(Qt.Key_3)
    compare(edit(num).text, "3")
  }

  function test_return_inserts_no_newline_and_tab_moves_focus() {
    focusEdit(num)
    keyClick(Qt.Key_Return)
    compare(edit(num).text.indexOf("\n"), -1)
    keyClick(Qt.Key_Tab)
    compare(edit(num).text.indexOf("\t"), -1)
    verify(!edit(num).activeFocus)
  }

  function test_focus_loss_commits() {
    focusEdit(num)
    keyClick(Qt.Key_2)
    other.forceActiveFocus()
    compare(mods.count, 1)
    compare(store.value, 2)
  }

  function test_empty_entry_reverts() {
    focusEdit(num)
    keyClick(Qt.Key_Backspace)
    keyClick(Qt.Key_Return)
    compare(mods.count, 0)
    compare(edit(num).text, "5")
  }

  function test_minus_only_when_range_is_negative() {
    focusEdit(signedNum)
    keyClick(Qt.Key_Minus)
    keyClick(Qt.Key_7)
    keyClick(Qt.Key_Return)
    compare(signedMods.count, 1)
    compare(signedMods.signalArguments[0][0], -7)
    focusEdit(signedNum)
    keyClick(Qt.Key_9)
    keyClick(Qt.Key_9)
    keyClick(Qt.Key_Return)
    compare(signedMods.signalArguments[1][0], 20)
  }

  function test_never_instantiates_an_editable_text_input() {
    verify(!(edit(num) instanceof Object && edit(num).hasOwnProperty("echoMode")))
    verify(edit(num).hasOwnProperty("cursorPosition"))
    compare(num.field.editable, false)
  }
}
