import QtQuick
import QtTest

// The panel's secret fields are `text: root.vault.<secret>` with an
// onTextChanged that writes back. Every path that clears a secret clears only
// the property, so the field must still be following it by then.
//
// This pins the Qt behaviour syncLoginFields() and syncSensitiveFields() in
// Panel.qml rely on, against TextInput (what the kit's TextField is built on):
// typing keeps the binding, a plain `field.text = value` drops it for good,
// and Qt.binding puts it back. A sync that copies a value instead of
// re-pointing the field is what left an item form showing stale text.
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
