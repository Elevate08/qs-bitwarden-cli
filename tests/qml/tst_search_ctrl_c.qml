// Ctrl+C in the search box, with auto-type on, arms the highlighted login
// (Panel.qml's search field calls armAutoTypeFromKey()). The box has focus
// when the panel opens, and the panel's own Ctrl+C never sees a key while a
// field holds it, so the field's handler must get the key before the editor
// copies, and must leave a selection's Ctrl+C to the editor.
//
// The field here is LineField's shape without the kit: a FocusScope whose
// TextArea forwards keys to it first (Keys.priority BeforeItem). The
// handler's own logic runs in tests/auto-type.test.js against the real source.
//
//   QT_QPA_PLATFORM=offscreen /usr/lib/qt6/bin/qmltestrunner -input tests/qml
//
import QtQuick
import QtQuick.Controls
import QtTest

TestCase {
  id: tc
  name: "SearchCtrlC"
  when: windowShown
  width: 300; height: 200
  visible: true

  property bool autoTypeEnabled: true
  property int arms: 0
  property var rows: ["top suggestion", "second"]
  property int selectedIndex: 0
  property string armed: ""

  // Stands in for armAutoTypeFromKey(): Control alone, auto-type on, a row.
  function armAutoTypeFromKey(event) {
    if ((event.modifiers & ~Qt.KeypadModifier) !== Qt.ControlModifier || event.key !== Qt.Key_C) return false
    if (!tc.autoTypeEnabled) return false
    tc.arms++
    tc.armed = tc.rows[tc.selectedIndex]
    return true
  }

  Column {
    FocusScope {
      id: searchField
      width: 280
      height: 30
      property alias text: editor.text
      property alias selectedText: editor.selectedText

      Keys.onPressed: function(event) {
        if (searchField.selectedText === "" && tc.armAutoTypeFromKey(event)) {
          event.accepted = true
          return
        }
      }

      TextArea {
        id: editor
        focus: true
        anchors.fill: parent
        Keys.priority: Keys.BeforeItem
        Keys.forwardTo: [searchField]
      }
    }

    // Where the clipboard is pasted back, to see what the editor copied.
    TextArea { id: pasteTarget; width: 280; height: 30 }
  }

  function init() {
    tc.autoTypeEnabled = true
    tc.arms = 0
    tc.armed = ""
    tc.selectedIndex = 0
    searchField.text = ""
    pasteTarget.text = ""
  }

  function pastedFromClipboard() {
    pasteTarget.text = ""
    pasteTarget.forceActiveFocus()
    keyClick(Qt.Key_V, Qt.ControlModifier)
    return pasteTarget.text
  }

  function test_1_ctrl_c_in_a_freshly_focused_box_arms_the_first_row() {
    searchField.forceActiveFocus()
    verify(editor.activeFocus, "the editor holds focus, as the search box's does when the panel opens")
    keyClick(Qt.Key_C, Qt.ControlModifier)
    compare(tc.arms, 1, "Ctrl+C never reached the field's own handler")
    compare(tc.armed, "top suggestion")
  }

  function test_2_typed_text_without_a_selection_still_arms() {
    searchField.forceActiveFocus()
    keyClick(Qt.Key_B)
    keyClick(Qt.Key_A)
    compare(searchField.text, "ba")
    tc.selectedIndex = 1
    keyClick(Qt.Key_C, Qt.ControlModifier)
    compare(tc.arms, 1)
    compare(tc.armed, "second", "the highlighted row, wherever it is")
    compare(searchField.text, "ba", "the key changed the query")
  }

  function test_3_a_selection_keeps_ctrl_c_for_the_editor() {
    // Clipboard holds something else first, so a copy that did not happen shows.
    pasteTarget.text = "before"
    pasteTarget.selectAll()
    pasteTarget.copy()
    searchField.text = "bank"
    searchField.forceActiveFocus()
    editor.select(0, 2)
    compare(searchField.selectedText, "ba")
    keyClick(Qt.Key_C, Qt.ControlModifier)
    compare(tc.arms, 0, "Ctrl+C over a selection was taken from the field's copy")
    compare(pastedFromClipboard(), "ba", "the editor did not copy the selection")
  }

  function test_4_an_armed_ctrl_c_does_not_also_copy() {
    pasteTarget.text = "before"
    pasteTarget.selectAll()
    pasteTarget.copy()
    searchField.text = "bank"
    searchField.forceActiveFocus()
    editor.cursorPosition = 4
    keyClick(Qt.Key_C, Qt.ControlModifier)
    compare(tc.arms, 1)
    compare(pastedFromClipboard(), "before", "the clipboard changed under an accepted Ctrl+C")
  }

  function test_5_other_chords_and_auto_type_off_are_left_alone() {
    searchField.text = ""
    searchField.forceActiveFocus()
    keyClick(Qt.Key_C, Qt.ControlModifier | Qt.ShiftModifier)
    keyClick(Qt.Key_V, Qt.ControlModifier)
    compare(tc.arms, 0, "only Ctrl+C arms")
    tc.autoTypeEnabled = false
    searchField.forceActiveFocus()
    keyClick(Qt.Key_C, Qt.ControlModifier)
    compare(tc.arms, 0, "with auto-type off Ctrl+C is the field's")
  }
}
