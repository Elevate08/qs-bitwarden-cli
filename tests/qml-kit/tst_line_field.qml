// LineField: a single-line TextArea with the shell field's API. Return submits
// instead of inserting a break, a caller's own Return handler still wins, a
// masked field accepts typing without a selection, and an in-memory paste
// strips line breaks. Long text keeps the caret inside the field, and a paste
// that finishes after the field or its form is closed is dropped. The
// wl-paste cap is pinned in tests/line-field.test.js.
//
//   tests/qml-kit/run.sh tests/qml-kit/tst_line_field.qml
import QtQuick
import QtQuick.Controls
import QtTest
import "../.."

TestCase {
  id: tc
  name: "LineField"
  when: windowShown
  width: 420
  height: 280
  visible: true

  QtObject {
    id: store
    property string value: ""
  }

  SignalSpy { id: edits; target: plain; signalName: "textEdited" }
  SignalSpy { id: secretEdits; target: secret; signalName: "textEdited" }

  Column {
    spacing: 8
    LineField { id: plain; width: 300 }
    LineField { id: next; width: 300 }
    LineField {
      id: searchLike
      width: 300
      property int enters: 0
      Keys.onReturnPressed: enters++
    }
    LineField { id: secret; width: 300; password: true }
    LineField { id: eyed; width: 160; password: true; rightPadding: 48 }
    LineField {
      id: bound
      width: 300
      text: store.value
      onTextChanged: store.value = text
    }
    Item {
      id: host
      width: 300
      height: 40
      LineField { id: nested; width: 300 }
    }
  }

  Component {
    id: stalledPaste
    QtObject {
      property int epoch: 0
      property bool closed: false
      property bool running: true
      property bool succeeded: false
      property string payload: "review-marker"
      property var command: []
      function signal(number) { running = false }
    }
  }

  function init() {
    store.value = ""
    plain.text = ""
    next.text = ""
    searchLike.text = ""
    searchLike.enters = 0
    secret.text = ""
    secret.password = true
    eyed.text = ""
    eyed.password = true
    eyed.width = 160
    eyed.rightPadding = 48
    nested.text = ""
    plain.visible = true
    plain.enabled = true
    plain.readOnly = false
    plain.width = 300
    host.visible = true
    plain.focus = false
    next.focus = false
    nested.focus = false
    edits.clear()
    secretEdits.clear()
  }

  function test_login_callers_can_handle_textEdited() {
    var field = Qt.createQmlObject('import QtQuick; import "../.."; LineField { property string editedValue: ""; onTextEdited: editedValue = text }', tc)
    field.insertPlainPaste("login-value")
    compare(field.editedValue, "login-value")
    field.destroy()
  }

  function test_only_user_changes_emit_textEdited() {
    plain.text = "a"
    secret.text = "a"
    compare(edits.count, 0)
    compare(secretEdits.count, 0)
    plain.forceActiveFocus()
    plain.cursorPosition = plain.length
    keyClick(Qt.Key_B)
    compare(edits.count, 1)
    keyClick(Qt.Key_Backspace)
    compare(edits.count, 2)
    keyClick(Qt.Key_Z, Qt.ControlModifier)
    compare(edits.count, 3)
    secret.forceActiveFocus()
    secret.cursorPosition = secret.length
    keyClick(Qt.Key_B)
    compare(secretEdits.count, 1)
    keyClick(Qt.Key_Backspace)
    compare(secretEdits.count, 2)
    secret.cursorPosition = 0
    keyClick(Qt.Key_Backspace)
    compare(secretEdits.count, 2, "a no-op deletion emitted an edit")
  }

  function test_selection_paste_emits_one_edit() {
    plain.text = "old"
    plain.select(0, plain.length)
    plain.insertPlainPaste("new")
    compare(plain.text, "new")
    compare(edits.count, 1)
    secret.insertPlainPaste("new")
    compare(secretEdits.count, 1)
  }

  function viewText(field) {
    for (var i = 0; i < field.children.length; ++i) {
      var child = field.children[i]
      if (child.wrapMode !== undefined && child.textFormat !== undefined) return child.text
    }
    return ""
  }

  function test_echo_mode_follows_password() {
    compare(plain.echoMode, TextInput.Normal)
    compare(secret.echoMode, TextInput.Password)
    secret.password = false
    compare(secret.echoMode, TextInput.Normal)
  }

  function test_typing_and_return_do_not_insert_a_break() {
    plain.forceActiveFocus()
    var submitted = 0
    plain.accepted.connect(function() { submitted++ })
    keyClick(Qt.Key_A)
    keyClick(Qt.Key_Return)
    keyClick(Qt.Key_Enter)
    compare(plain.text, "a", "Return or Enter inserted a break")
    compare(submitted, 2, "Return or Enter did not submit")
  }

  function test_a_callers_return_handler_runs_and_inserts_nothing() {
    searchLike.forceActiveFocus()
    keyClick(Qt.Key_B)
    keyClick(Qt.Key_Return)
    compare(searchLike.text, "b")
    compare(searchLike.enters, 1, "the field's own Return handler did not run")
  }

  function test_tab_moves_focus() {
    plain.forceActiveFocus()
    keyClick(Qt.Key_Tab)
    verify(next.activeFocus, "Tab did not leave the field")
  }

  function test_password_types_without_selecting() {
    secret.forceActiveFocus()
    keyClick(Qt.Key_S)
    keyClick(Qt.Key_E)
    compare(secret.text, "se")
    compare(viewText(secret), "\u2022\u2022", "the secret is in the visible document")
    keyClick(Qt.Key_A, Qt.ControlModifier)
    compare(secret.selectedText, "", "Select All published a selection")
    keyClick(Qt.Key_Left, Qt.ShiftModifier)
    compare(secret.selectedText, "", "Shift+Left extended a selection")
    compare(secret.cursorPosition, secret.length - 1, "Shift+Left did not move the caret")
  }

  function editorOf(field) {
    for (var i = 0; i < field.children.length; ++i) {
      var child = field.children[i]
      if (child.wrapMode !== undefined && child.textFormat !== undefined) return child
    }
    return null
  }

  function overlay(field, name) {
    var ed = editorOf(field)
    for (var i = 0; i < ed.children.length; ++i)
      if (ed.children[i].objectName === name) return ed.children[i]
    return null
  }

  function test_masked_caret_follows_focus_and_state() {
    secret.text = "ab"
    var caret = overlay(secret, "maskedCaret")
    verify(caret, "no masked caret")
    secret.forceActiveFocus()
    keyClick(Qt.Key_Left)
    compare(caret.visible, true, "focused masked field shows no caret")
    compare(caret.width, 1)
    compare(overlay(secret, "maskedCaret").x, secret.cursorRectangle.x)
    secret.readOnly = true
    compare(caret.visible, false, "readOnly field shows a caret")
    secret.readOnly = false
    keyClick(Qt.Key_Right)
    compare(caret.visible, true)
    secret.enabled = false
    compare(caret.visible, false, "disabled field shows a caret")
    secret.enabled = true
    plain.forceActiveFocus()
    compare(caret.visible, false, "unfocused field shows a caret")
  }

  // The caret is centred from the editor's box. In the shell, a hidden field
  // shown for editing once drew it high until the first keystroke; offscreen
  // Qt refreshes cursorRectangle at once, so this pins the invariant only.
  function test_masked_caret_is_centred_after_a_resize() {
    var field = Qt.createQmlObject('import QtQuick; import "../.."; LineField { width: 300; password: true; visible: false }', tc)
    field.text = "abc"
    field.visible = true
    field.height = 64
    field.forceActiveFocus()
    var caret = overlay(field, "maskedCaret")
    var ed = editorOf(field)
    compare(caret.visible, true)
    var boxMid = ed.topPadding + (ed.height - ed.topPadding - ed.bottomPadding) / 2
    fuzzyCompare(caret.y + caret.height / 2, boxMid, 1, "caret is not vertically centred")
    field.destroy()
  }

  function test_only_one_caret_after_toggling_password() {
    secret.text = "ab"
    secret.forceActiveFocus()
    var caret = overlay(secret, "maskedCaret")
    compare(caret.visible, true)
    secret.password = false
    compare(caret.visible, false, "the own caret stayed beside the TextArea's")
    secret.password = true
    compare(caret.visible, true)
  }

  function test_select_all_then_typing_replaces_the_value() {
    secret.text = "abc"
    secret.forceActiveFocus()
    keyClick(Qt.Key_A, Qt.ControlModifier)
    compare(overlay(secret, "maskedHighlight").visible, true, "no highlight")
    compare(editorOf(secret).selectedText, "", "Select All left a TextEdit selection")
    keyClick(Qt.Key_X)
    compare(secret.text, "x")
    compare(overlay(secret, "maskedHighlight").visible, false)
    keyClick(Qt.Key_Y)
    compare(secret.text, "xy", "the flag outlived the edit")
  }

  function test_select_all_then_paste_replaces_the_value() {
    secret.text = "abc"
    secret.forceActiveFocus()
    keyClick(Qt.Key_A, Qt.ControlModifier)
    secret.insertPlainPaste("new")
    compare(secret.text, "new")
  }

  function test_select_all_then_backspace_or_delete_clears() {
    secret.text = "abc"
    secret.forceActiveFocus()
    keyClick(Qt.Key_A, Qt.ControlModifier)
    keyClick(Qt.Key_Backspace)
    compare(secret.text, "")
    secret.text = "abc"
    secret.cursorPosition = 1
    keyClick(Qt.Key_A, Qt.ControlModifier)
    keyClick(Qt.Key_Delete)
    compare(secret.text, "")
  }

  function test_select_all_then_arrow_inserts() {
    secret.text = "abc"
    secret.forceActiveFocus()
    secret.cursorPosition = secret.length
    keyClick(Qt.Key_A, Qt.ControlModifier)
    keyClick(Qt.Key_Left)
    compare(overlay(secret, "maskedHighlight").visible, false)
    keyClick(Qt.Key_X)
    compare(secret.text, "abxc")
  }

  function test_select_all_is_dropped_by_focus_loss_and_outside_changes() {
    secret.text = "abc"
    secret.forceActiveFocus()
    keyClick(Qt.Key_A, Qt.ControlModifier)
    plain.forceActiveFocus()
    secret.forceActiveFocus()
    secret.cursorPosition = secret.length
    keyClick(Qt.Key_X)
    compare(secret.text, "abcx", "focus loss kept the select-all")
    keyClick(Qt.Key_A, Qt.ControlModifier)
    secret.text = "zz"
    secret.cursorPosition = 2
    keyClick(Qt.Key_X)
    compare(secret.text, "zzx", "an outside change kept the select-all")
    keyClick(Qt.Key_A, Qt.ControlModifier)
    secret.password = false
    secret.password = true
    secret.cursorPosition = 3
    keyClick(Qt.Key_Y)
    compare(secret.text, "zzxy")
  }

  function test_select_all_on_an_empty_value_sets_nothing() {
    secret.forceActiveFocus()
    keyClick(Qt.Key_A, Qt.ControlModifier)
    compare(overlay(secret, "maskedHighlight").visible, false)
  }

  function test_copy_and_cut_after_select_all_change_nothing() {
    secret.text = "abc"
    secret.forceActiveFocus()
    keyClick(Qt.Key_A, Qt.ControlModifier)
    keyClick(Qt.Key_C, Qt.ControlModifier)
    keyClick(Qt.Key_X, Qt.ControlModifier)
    compare(secret.text, "abc")
    compare(editorOf(secret).selectedText, "")
    compare(secretEdits.count, 0)
  }

  function test_select_all_cleared_by_read_only() {
    secret.text = "abc"
    secret.forceActiveFocus()
    keyClick(Qt.Key_A, Qt.ControlModifier)
    secret.readOnly = true
    secret.readOnly = false
    secret.cursorPosition = secret.length
    keyClick(Qt.Key_X)
    compare(secret.text, "abcx")
  }

  function test_range_edges_snap_off_a_surrogate_pair() {
    secret.text = "a\uD83D\uDE00b"
    secret.forceActiveFocus()
    secret.cursorPosition = 3
    keyClick(Qt.Key_X)
    compare(secret.text, "a\uD83D\uDE00xb")
    compare(secret.snapIndex(secret.text, 2, -1), 1, "back edge split the pair")
    compare(secret.snapIndex(secret.text, 2, 1), 3, "forward edge split the pair")
    compare(secret.snapIndex(secret.text, 3, 1), 3)
  }

  function test_password_backspace_removes_a_whole_character() {
    secret.text = "a\uD83D\uDE00"
    secret.cursorPosition = secret.length
    secret.forceActiveFocus()
    keyClick(Qt.Key_Backspace)
    compare(secret.text, "a")
    compare(secret.text.length, 1, "half of the character was left behind")
  }

  function test_password_accepts_an_altgr_character() {
    secret.forceActiveFocus()
    keyClick(Qt.Key_At, Qt.ControlModifier | Qt.AltModifier)
    compare(secret.text, "@")
  }

  function test_a_plain_paste_can_be_undone() {
    plain.text = "ab"
    plain.forceActiveFocus()
    plain.cursorPosition = plain.length
    plain.insertPlainPaste("Z")
    compare(plain.text, "abZ")
    keyClick(Qt.Key_Z, Qt.ControlModifier)
    compare(plain.text, "ab", "the paste could not be undone")
  }

  function test_password_undo_leaves_the_secret() {
    secret.forceActiveFocus()
    keyClick(Qt.Key_A)
    keyClick(Qt.Key_B)
    keyClick(Qt.Key_Z, Qt.ControlModifier)
    compare(secret.text, "ab")
    compare(viewText(secret), "\u2022\u2022")
  }

  function test_paste_strips_breaks_and_replaces_a_selection() {
    plain.text = "ab"
    plain.forceActiveFocus()
    plain.select(0, 2)
    plain.insertPlainPaste("x\ny\r\u2028")
    compare(plain.text, "xy")
  }

  function test_typing_keeps_a_text_binding() {
    bound.forceActiveFocus()
    keyClick(Qt.Key_Q)
    compare(store.value, "q")
    store.value = ""
    compare(bound.text, "", "clearing the property left the typed text")
  }

  function test_click_focuses_the_field() {
    mouseClick(plain, 12, Math.min(12, plain.height / 2))
    verify(plain.activeFocus, "a click did not focus the field")
  }

  function test_the_editing_menu_is_gone() {
    compare(plain.ContextMenu.menu, null)
  }

  function test_long_text_keeps_the_caret_inside_the_field() {
    plain.width = 160
    plain.text = "m".repeat(80)
    plain.cursorPosition = plain.length
    tryVerify(function() { return plain.hscroll > 0 && plain.cursorRectangle.x <= plain.width + 1 }, 500,
      "caret stayed past the edge at " + plain.cursorRectangle.x)
    verify(plain.cursorRectangle.x >= -1, "caret left the left edge at " + plain.cursorRectangle.x)
    plain.cursorPosition = 0
    tryVerify(function() { return plain.hscroll < 1 && plain.cursorRectangle.x <= plain.leftPadding + 2 }, 500,
      "the caret at the start stayed scrolled away")
  }

  function test_long_secret_keeps_the_caret_clear_of_trailing_padding() {
    eyed.text = "m".repeat(80)
    eyed.cursorPosition = eyed.length
    tryVerify(function() {
      return eyed.cursorRectangle.x <= eyed.width - eyed.rightPadding + 1
    }, 500, "caret " + eyed.cursorRectangle.x + " width " + eyed.width + " pad " + eyed.rightPadding)
    verify(eyed.cursorRectangle.x >= -1, "caret left the left edge")
    compare(viewText(eyed).indexOf("m"), -1, "the secret is in the visible document")
  }

  function test_an_open_field_accepts_the_current_paste() {
    plain.acceptPaste(plain.pasteEpoch, "kept")
    compare(plain.text, "kept")
  }

  function test_a_hidden_field_drops_a_late_paste() {
    var epoch = plain.pasteEpoch
    plain.visible = false
    plain.acceptPaste(epoch, "review-marker")
    compare(plain.text, "", "a late paste refilled a cleared hidden field")
  }

  function test_a_hidden_ancestor_drops_a_late_paste() {
    var epoch = nested.pasteEpoch
    host.visible = false
    nested.acceptPaste(epoch, "review-marker")
    compare(nested.text, "", "a late paste refilled a field in a closed form")
  }

  function test_a_disabled_field_drops_a_late_paste() {
    var epoch = plain.pasteEpoch
    plain.enabled = false
    plain.acceptPaste(epoch, "review-marker")
    compare(plain.text, "")
  }

  function test_hiding_an_ancestor_stops_an_in_flight_paste() {
    nested.text = "keep"
    var epoch = nested.pasteEpoch
    var proc = stalledPaste.createObject(nested, { epoch: epoch })
    nested.pasteProc = proc
    nested.armPasteGuards()
    host.visible = false
    verify(nested.pasteEpoch !== epoch, "closing the form left the paste eligible")
    compare(proc.running, false, "the paste kept reading after the form closed")
    compare(nested.text, "keep")
    nested.pasteProc = null
    nested.disarmPasteGuards()
    proc.destroy()
  }

  function test_a_callers_visibility_handler_does_not_override_cancellation() {
    var field = Qt.createQmlObject('import QtQuick; import "../.."; LineField { onVisibleChanged: {} }', tc)
    var proc = stalledPaste.createObject(field, { epoch: field.pasteEpoch })
    field.pasteProc = proc
    field.visible = false
    compare(proc.running, false)
    field.pasteProc = null
    proc.destroy()
    field.destroy()
  }

  function test_a_finished_paste_does_not_keep_its_collector() {
    plain.forceActiveFocus()
    plain.pasteFrom(false)
    compare(plain.pasteProc, null, "the paste collector outlived the paste")
    plain.pasteFrom(false)
    compare(plain.pasteProc, null, "a second paste was stuck behind the first")
  }

  function test_failed_paste_discards_partial_output() {
    var proc = stalledPaste.createObject(plain, { epoch: plain.pasteEpoch, running: false })
    plain.pasteProc = proc
    plain.finishPaste(proc)
    compare(plain.text, "", "a timeout pasted its incomplete payload")
    compare(plain.pasteProc, null)
  }

  function test_successful_paste_accepts_output() {
    var proc = stalledPaste.createObject(plain, {
      epoch: plain.pasteEpoch, running: false, succeeded: true
    })
    plain.pasteProc = proc
    plain.finishPaste(proc)
    compare(plain.text, "review-marker")
    compare(edits.count, 1)
    compare(plain.pasteProc, null)
  }

  function test_paste_command_names_the_cap() {
    var clipboard = plain.pasteCommand(false).join(" ")
    var primary = plain.pasteCommand(true).join(" ")
    verify(clipboard.indexOf("wl-paste --type text --no-newline") !== -1, clipboard)
    verify(clipboard.indexOf("head -c " + plain.pasteByteCap) !== -1, clipboard)
    verify(primary.indexOf("wl-paste --primary --type text ") !== -1, primary)
  }
}
