import QtQuick
import QtTest

// Secret fields bind `text` to a vault property and write back on change;
// clearing only clears the property. Pins what syncLoginFields() and
// syncSensitiveFields() rely on: typing keeps the binding, `field.text =`
// drops it for good, and Qt.binding restores it.
TestCase {
  id: tc
  name: "FieldBinding"
  when: windowShown
  width: 300; height: 100
  visible: true

  QtObject { id: vault; property string secret: "" }

  Component {
    id: fieldComponent
    TextInput {
      width: 200; height: 30
      text: vault.secret
      onTextChanged: vault.secret = text
    }
  }

  function init() { vault.secret = "" }

  function test_typing_keeps_the_binding() {
    var field = createTemporaryObject(fieldComponent, tc)
    field.forceActiveFocus()
    keyClick(Qt.Key_A)
    keyClick(Qt.Key_B)
    compare(vault.secret, "ab")
    vault.secret = ""
    compare(field.text, "", "clearing the property clears a typed-in field")
  }

  function test_a_plain_assignment_drops_the_binding() {
    var field = createTemporaryObject(fieldComponent, tc)
    field.text = vault.secret
    vault.secret = "opened item"
    verify(field.text !== "opened item",
      "if this now follows, Qt changed and the Qt.binding sync is optional")
  }

  function test_qt_binding_refreshes_and_keeps_following() {
    var field = createTemporaryObject(fieldComponent, tc)
    field.text = "stale"
    vault.secret = "current"
    field.text = Qt.binding(function() { return vault.secret })
    compare(field.text, "current", "the sync refreshes the field now")
    vault.secret = ""
    compare(field.text, "", "and it keeps following afterwards")
  }
}
