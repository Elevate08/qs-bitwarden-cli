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
    // "pinentry", "wait" (for the vault helper) or "field" (Service.qml).
    property string typedSecretEntry: "pinentry"
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
    function declinePinentry() { tc.calls.push("decline"); pinentryAvailable = false; typedSecretEntry = "field" }
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

  function textItem(item, text) {
    if (!item || !item.visible) return null
    if (String(item.text || "") === text) return item
    var kids = item.children || []
    for (var i = 0; i < kids.length; i++) {
      var found = textItem(kids[i], text)
      if (found) return found
    }
    return null
  }

  // Where the vault says typing goes; pinentryAvailable follows it.
  function entry(where) {
    fakeVault.typedSecretEntry = where
    fakeVault.pinentryAvailable = where === "pinentry"
    wait(0)
  }

  function init() {
    tc.calls = []
    fakeVault.masterPassword = ""
    fakeVault.pinEntry = ""
    fakeVault.typedSecretEntry = "pinentry"
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

  // The vault helper is not running yet, or was left stopped: pinentry runs
  // under it, so it cannot ask, and the panel's field is not offered in its
  // place (what is typed there stays in the shell).
  function test_waiting_for_the_helper_offers_no_field() {
    entry("wait")
    form.useMethod("password")
    compare(form.method, "password")
    verify(!form.passwordField.visible, "the master password field is offered while the helper is not running")
    verify(textItem(form, "Waiting for the vault helper...") !== null, "the form does not say it is waiting")
    verify(!textItem(form, "Waiting for the vault helper...").enabled, "the Unlock button can be pressed")
    form.submitCurrentMethod()
    form.useMethod("pin")
    verify(!form.pinField.visible, "the PIN field is offered while the helper is not running")
    form.submitCurrentMethod()
    compare(tc.calls.filter(function(c) { return c !== "fingerprint" }).join(","), "",
      "something was submitted or asked for while waiting")
  }

  // A field that is not offered takes no keys, even if focus is pushed there
  // (the vault focuses "pass" or "pin" on the locked screen).
  function test_a_field_not_offered_takes_no_keys() {
    var cases = ["pinentry", "wait"]
    for (var i = 0; i < cases.length; i++) {
      entry(cases[i])
      form.chosen = "password"
      wait(0)
      form.passwordField.forceActiveFocus()
      keyClick(Qt.Key_S)
      compare(fakeVault.masterPassword, "", "a key reached the hidden password field (" + cases[i] + ")")
      form.chosen = "pin"
      wait(0)
      form.pinField.forceActiveFocus()
      keyClick(Qt.Key_7)
      compare(fakeVault.pinEntry, "", "a key reached the hidden PIN field (" + cases[i] + ")")
    }
  }

  // Pinentry turned off, missing or declined, or the vault held in the shell
  // as allowed: the field is the way in.
  function test_the_field_when_it_is_the_way_in() {
    entry("field")
    form.useMethod("password")
    verify(form.passwordField.visible, "the field is not offered")
    form.passwordField.forceActiveFocus()
    keyClick(Qt.Key_S)
    compare(fakeVault.masterPassword, "s")
    verify(textItem(form, "Waiting for the vault helper...") === null, "it says it is waiting")
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
