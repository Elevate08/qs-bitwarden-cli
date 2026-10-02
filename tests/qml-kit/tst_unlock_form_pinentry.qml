// The lock screen's unlock form (UnlockForm.qml) around pinentry, with
// fingerprint unlock on as well, so the form's default method is not one
// pinentry types for:
// - the panel hiding while pinentry asks is not the form closing, so the
//   method picked (Password, PIN) is still the one shown when it comes back;
// - after a failed pinentry, the notice and "Type it here instead" show;
// - a real close still forgets the method picked.
//
//   tests/qml-kit/run.sh tests/qml-kit/tst_unlock_form_pinentry.qml
//
import QtQuick
import QtTest
import "../.."

TestCase {
  id: tc
  name: "UnlockFormPinentry"
  when: windowShown
  width: 480; height: 900
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
    property string status: "locked"
    property string userEmail: "a@x"
    property bool isUnlocking: false
    property string pendingUnlockFrom: ""
    property string masterPassword: ""
    property string pinEntry: ""
    property bool pinBusy: false
    property bool pinReady: true
    property string pinUnlockError: ""
    property bool fidoReady: false
    property bool fidoScanning: false
    property bool fidoAuthorized: false
    property string fidoError: ""
    property string fidoMessage: ""
    property bool fingerprintReady: true
    property bool fingerprintAvailable: true
    property bool fingerprintStored: true
    property bool fingerprintUnlock: true
    property bool fingerprintScanning: false
    property bool fingerprintAuthorized: false
    property string fingerprintError: ""
    property string fingerprintMessage: ""
    property bool pinentryAvailable: true
    property bool pinentryActive: false
    property bool pinentryAutoAsked: false
    property string pinentryNotice: ""
    function startFingerprintUnlock() { tc.calls.push("fingerprint") }
    function cancelFingerprintUnlock() {}
    function startFidoUnlock() {}
    function releaseFidoUnlock() {}
    function prepareUnlock() {}
    function unlockWithPinentry() { tc.calls.push("pinentry:password") }
    function unlockPinWithPinentry() { tc.calls.push("pinentry:pin") }
    function submitPinUnlock() { tc.calls.push("submitPin") }
    function unlockVault() { tc.calls.push("unlockVault") }
    function declinePinentry() { tc.calls.push("decline"); pinentryAvailable = false }
  }

  Item {
    id: host
    width: 460
    height: 880

    UnlockForm {
      id: form
      panel: fakePanel
      vault: fakeVault
    }
  }

  function shownWithText(item, text) {
    if (!item || !item.visible) return false
    if (String(item.text || "") === text) return true
    var kids = item.children || []
    for (var i = 0; i < kids.length; i++) if (shownWithText(kids[i], text)) return true
    return false
  }

  function init() {
    tc.calls = []
    fakeVault.pinentryAvailable = true
    fakeVault.pinentryActive = false
    fakeVault.pinentryAutoAsked = false
    fakeVault.pinentryNotice = ""
    host.visible = true
    form.chosen = ""
    wait(0)
  }

  function test_fingerprint_is_the_default() {
    compare(form.method, "fingerprint")
  }

  // Picking Password opens pinentry; the panel hides while it asks, and comes
  // back with Password still picked.
  function hideForPinentry() {
    form.useMethod("password")
    compare(form.method, "password")
    verify(tc.calls.indexOf("pinentry:password") !== -1, "picking Password did not open pinentry")
    fakeVault.pinentryActive = true
    host.visible = false
    wait(0)
    fakeVault.pinentryActive = false
  }

  function test_hiding_for_pinentry_keeps_the_method_picked() {
    hideForPinentry()
    host.visible = true
    wait(0)
    compare(form.method, "password", "coming back from pinentry fell back to the default method")
  }

  function test_a_failed_pinentry_shows_the_notice_and_the_choice() {
    hideForPinentry()
    fakeVault.pinentryNotice = "Pinentry stopped before answering. Try again, or type it here instead."
    host.visible = true
    wait(0)
    verify(shownWithText(form, fakeVault.pinentryNotice), "the notice is not shown")
    verify(shownWithText(form, "Type it here instead"), "the button is not shown")
    compare(form.method, "password")
  }

  function test_a_real_close_forgets_the_method_picked() {
    form.useMethod("password")
    host.visible = false
    wait(0)
    host.visible = true
    wait(0)
    compare(form.method, "fingerprint")
  }
}
