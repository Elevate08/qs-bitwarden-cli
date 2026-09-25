// SecretField.qml: the item form's card, identity and TOTP secrets are masked
// until their eye is pressed, kept from input methods even when shown, and
// masked again once the field leaves the screen.
//
//   tests/qml-kit/run.sh tests/qml-kit/tst_secret_field.qml
//
import QtQuick
import QtTest
import "../.."

TestCase {
  id: tc
  name: "SecretField"
  when: windowShown
  width: 400; height: 200
  visible: true

  Item {
    id: form
    width: 360
    height: 60
    SecretField { id: field; width: 340; text: "4111 1111 1111 1111" }
  }

  function eye() {
    for (var i = 0; i < field.children.length; i++) {
      if (field.children[i].iconText !== undefined) return field.children[i]
    }
    return null
  }

  function init() {
    form.visible = true
    field.revealed = false
  }

  function test_masked_until_revealed() {
    compare(field.echoMode, TextInput.Password, "the secret is drawn in the clear")
    var button = eye()
    verify(button !== null, "no eye to reveal it")
    mouseClick(button)
    compare(field.echoMode, TextInput.Normal, "the eye did not reveal it")
    mouseClick(button)
    compare(field.echoMode, TextInput.Password, "the eye did not hide it again")
  }

  function test_input_methods_never_see_it() {
    field.revealed = true
    verify((field.inputMethodHints & Qt.ImhSensitiveData) !== 0, "not marked sensitive while shown")
    verify((field.inputMethodHints & Qt.ImhNoPredictiveText) !== 0, "prediction would learn it")
  }

  function test_leaving_the_screen_masks_it_again() {
    field.revealed = true
    form.visible = false
    form.visible = true
    compare(field.echoMode, TextInput.Password, "a reveal outlived the form")
  }

  function test_the_text_still_edits_through() {
    field.text = ""
    field.forceActiveFocus()
    keyClick(Qt.Key_4); keyClick(Qt.Key_2)
    compare(field.text, "42")
  }
}
