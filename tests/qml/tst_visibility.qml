import QtQuick
import QtTest

// UnlockForm resets its password eye in its own onVisibleChanged, and relies
// on `visible` being effective visibility: hiding any ancestor -- the panel's
// lock screen, the SSH unlock screen -- notifies the form too. This pins that,
// so nobody adds per-screen or parent-watching resets to work around it.
TestCase {
  name: "Visibility"
  when: windowShown
  width: 100; height: 100
  visible: true

  Item {
    id: screen
    Item {
      Item {
        id: form
        property int hides: 0
        onVisibleChanged: if (!visible) hides++
      }
    }
  }

  function test_hiding_an_ancestor_notifies_the_descendant() {
    verify(form.visible)
    screen.visible = false
    compare(form.visible, false)
    verify(form.hides > 0, "the descendant's onVisibleChanged ran")
    screen.visible = true
  }
}
