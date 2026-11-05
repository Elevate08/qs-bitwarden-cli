// Enter saves the item form from any of its fields. A form-level Shortcut
// cannot do it alone: an editable TextEdit (LineField's editor) claims Return
// and Enter in ShortcutOverride, so the Shortcut never fires while a text
// field has focus and the user had to scroll down to the Save button. Such a
// field hands Return to the nearest ancestor with submitForm(); the Shortcut
// still covers a masked field, whose editor is read-only.
//
// The form below stands in for Panel.qml's editFormCol, with the real
// LineField and SecretField:
//
//   tests/qml-kit/run.sh tests/qml-kit/tst_item_form_enter.qml
import QtQuick
import QtTest
import "../.."

TestCase {
  id: tc
  name: "ItemFormEnter"
  when: windowShown
  width: 420
  height: 360
  visible: true

  property int saves: 0
  property int folders: 0
  property int outsideAccepts: 0
  property string picker: ""
  property bool loading: false

  Column {
    id: form
    spacing: 8

    // Same guards as Panel.qml's: no save while a picker or a save is open.
    function submitForm() {
      if (tc.picker !== "" || tc.loading) return
      tc.saves++
    }

    LineField { id: nameField; width: 300 }
    SecretField { id: totpField; width: 300 }
    // Like the new-folder field: its own Return does something else.
    LineField {
      id: folderField
      width: 300
      submitsForm: false
      onAccepted: tc.folders++
    }
    Column {
      LineField { id: nestedField; width: 300 }
    }

    Shortcut {
      sequences: ["Return", "Enter"]
      enabled: tc.picker === "" && !tc.loading
      onActivated: form.submitForm()
    }
  }

  LineField {
    id: outsideField
    y: 300
    width: 300
    onAccepted: tc.outsideAccepts++
  }

  function init() {
    saves = 0
    folders = 0
    outsideAccepts = 0
    picker = ""
    loading = false
    nameField.text = ""
    totpField.text = ""
    totpField.revealed = false
    folderField.text = ""
    nestedField.text = ""
    outsideField.text = ""
  }

  function test_return_in_a_text_field_saves() {
    nameField.forceActiveFocus()
    keyClick(Qt.Key_A)
    keyClick(Qt.Key_Return)
    compare(saves, 1, "Return in the name field did not save")
    keyClick(Qt.Key_Enter)
    compare(saves, 2, "keypad Enter in the name field did not save")
    compare(nameField.text, "a", "Return or Enter inserted a break")
  }

  function test_a_field_deeper_in_the_form_saves() {
    nestedField.forceActiveFocus()
    keyClick(Qt.Key_Return)
    compare(saves, 1)
  }

  function test_a_secret_saves_once_masked_or_revealed() {
    totpField.forceActiveFocus()
    keyClick(Qt.Key_Return)
    compare(saves, 1, "Return in a masked field did not save exactly once")
    totpField.revealed = true
    keyClick(Qt.Key_Return)
    compare(saves, 2, "Return in a revealed field did not save exactly once")
  }

  function test_a_field_with_its_own_return_does_not_save() {
    folderField.forceActiveFocus()
    keyClick(Qt.Key_N)
    keyClick(Qt.Key_Return)
    compare(folders, 1, "the field's own Return did not run")
    compare(saves, 0, "Return in the folder field also saved the item")
  }

  function test_no_save_while_a_picker_or_a_save_is_open() {
    nameField.forceActiveFocus()
    picker = "folder"
    keyClick(Qt.Key_Return)
    picker = ""
    loading = true
    keyClick(Qt.Key_Return)
    totpField.forceActiveFocus()
    keyClick(Qt.Key_Return)
    compare(saves, 0)
  }

  function test_a_field_outside_a_form_only_accepts() {
    outsideField.forceActiveFocus()
    keyClick(Qt.Key_Return)
    compare(outsideAccepts, 1)
    compare(saves, 0)
  }
}
