// The SSH approval and unlock cards must not act on keys typed before they
// are armed. A request can pop the card up while the user is typing in
// another window: two stray keys (Tab, then Space or Enter) used to approve a
// signature, Shift+Tab then Enter to open a grant, and typing landed straight
// in the unlock PIN or password field.
//
// Builds the real SshApprovalScreen.qml and SshUnlockScreen.qml, with the
// kit's real Button and TextField, around a stand-in vault:
//
//   tests/qml-kit/run.sh tests/qml-kit/tst_ssh_arming.qml
//
import QtQuick
import QtTest
import "../.."

TestCase {
  id: tc
  name: "SshArming"
  when: windowShown
  width: 560; height: 700
  visible: true

  property var calls: []
  property int escapes: 0
  // The delay the fix promises; a shorter one lets a fast Tab-then-Enter in.
  readonly property int promisedDelayMs: 800

  QtObject {
    id: fakePanel
    property string fontFamily: "monospace"
    property color fg: "white"
    property color dim: "gray"
    property color urgent: "red"
  }

  function prompt(keyName) {
    return {
      forwardedWarning: "", operationLabel: "Git commit or tag signature", destinationLabel: "",
      keyName: keyName, fingerprint: "SHA256:x", processName: "ssh-keygen",
      processPath: "/usr/bin/ssh-keygen", provenanceNote: "", grantOffered: true,
      grantShortLabel: "Approve 2m", grantLabel: "Approve for this program", grantSeconds: 120
    }
  }

  QtObject {
    id: approvalVault
    property string activeScreen: "sshApproval"
    property string status: "unlocked"
    property bool sshAgentApprovalPopup: true
    property bool sshAgentLoadActive: false
    property int sshPendingCount: 1
    property int sshPromptRemainingSec: 120
    property var sshPrompt: tc.prompt("work")
    function denySshRequest() { tc.calls.push("deny") }
    function denyAllSshRequests() { tc.calls.push("denyAll") }
    function approveSshRequest(sec) { tc.calls.push("approve(" + sec + ")") }
  }

  // Stands in for the card or panel above the screen, which denies on Escape.
  Item {
    id: host
    width: 520
    height: 600
    Keys.onEscapePressed: tc.escapes++
  }

  Component {
    id: approvalComp
    SshApprovalScreen { width: 520; panel: fakePanel; vault: approvalVault; active: true }
  }

  QtObject {
    id: unlockVault
    property string status: "locked"
    property string activeScreen: "main"
    property var sshUnlockRequest: ({ keyName: "work", processName: "git" })
    property int sshUnlockPendingCount: 1
    property int sshPromptRemainingSec: 120
    property bool sshAgentLoadActive: false
    property string errorMessage: ""
    property string userEmail: ""
    property string masterPassword: ""
    property string pinEntry: ""
    property bool fidoReady: false
    property bool fingerprintReady: false
    property bool pinReady: false
    property bool fidoScanning: false
    property bool fidoAuthorized: false
    property bool fingerprintScanning: false
    property bool fingerprintAuthorized: false
    property bool isUnlocking: false
    property string pendingUnlockFrom: ""
    property bool pinBusy: false
    property string fidoMessage: ""
    property string fingerprintMessage: ""
    property string fidoError: ""
    property string fingerprintError: ""
    property bool fingerprintUnlock: false
    property bool fingerprintAvailable: false
    property bool fingerprintStored: false
    property string pinUnlockError: ""
    // Typed into the panel's field (pinentry off): the field this test arms.
    property string typedSecretEntry: "field"
    function prepareUnlock() {}
    function armPresenceUnlock() {}
    function releaseFidoUnlock() {}
    function cancelFingerprintUnlock() {}
    function startFidoUnlock() {}
    function startFingerprintUnlock() {}
    function unlockVault() { tc.calls.push("unlock(" + masterPassword + ")") }
    function submitPinUnlock() { tc.calls.push("pin") }
    function denySshRequest() { tc.calls.push("deny") }
    function denyAllSshRequests() { tc.calls.push("denyAll") }
  }

  Component {
    id: unlockComp
    SshUnlockScreen { width: 520; panel: fakePanel; vault: unlockVault; active: true }
  }

  property var screen: null

  function init() {
    tc.calls = []
    tc.escapes = 0
    approvalVault.sshPrompt = tc.prompt("work")
    approvalVault.status = "unlocked"
    unlockVault.masterPassword = ""
  }

  function cleanup() {
    if (tc.screen) tc.screen.destroy()
    tc.screen = null
    wait(0)
  }

  function tile(label) {
    var rows = [tc.screen]
    while (rows.length > 0) {
      var item = rows.shift()
      if (item.label === label && item.clicked !== undefined) return item
      for (var i = 0; i < item.children.length; i++) rows.push(item.children[i])
    }
    return null
  }

  function focused() { return tc.screen.Window.activeFocusItem }

  // As the popup does when it opens: the screen is built already shown.
  function openApproval() {
    tc.screen = approvalComp.createObject(host)
    verify(tc.screen !== null, "the approval screen did not build")
    return Date.now()
  }

  function test_0_the_delay_is_the_promised_one() {
    openApproval()
    verify(tc.screen.armDelayMs >= tc.promisedDelayMs, "the arming delay is shorter than promised")
  }

  function test_1_tab_space_before_arming_does_nothing() {
    var t0 = openApproval()
    keyClick(Qt.Key_Tab)
    keyClick(Qt.Key_Space)
    compare(tc.calls.join(","), "", "Tab, Space signed or denied before the card was armed")
    verify(Date.now() - t0 < tc.promisedDelayMs, "the keys were not typed inside the delay")
    verify(!tc.screen.armed, "the card armed sooner than promised")
  }

  function test_2_tab_enter_before_arming_does_nothing() {
    var t0 = openApproval()
    keyClick(Qt.Key_Tab)
    keyClick(Qt.Key_Return)
    compare(tc.calls.join(","), "", "Tab, Enter signed or denied before the card was armed")
    verify(Date.now() - t0 < tc.promisedDelayMs, "the keys were not typed inside the delay")
    verify(!tc.screen.armed, "the card armed sooner than promised")
  }

  function test_3_shift_tab_enter_before_arming_opens_no_grant() {
    var t0 = openApproval()
    keyClick(Qt.Key_Backtab, Qt.ShiftModifier)
    keyClick(Qt.Key_Return)
    compare(tc.calls.join(","), "", "Shift+Tab, Enter opened a grant before the card was armed")
    verify(Date.now() - t0 < tc.promisedDelayMs, "the keys were not typed inside the delay")
    verify(!tc.screen.armed, "the card armed sooner than promised")
  }

  function test_4_deny_keeps_focus_once_armed() {
    openApproval()
    keyClick(Qt.Key_Tab)
    keyClick(Qt.Key_Backtab, Qt.ShiftModifier)
    tryVerify(function() { return tc.screen.armed }, 2000, "the card never armed")
    compare(focused(), tile("Deny"), "focus must rest on Deny, whatever was typed before arming")
    keyClick(Qt.Key_Return)
    compare(tc.calls.join(","), "deny")
  }

  function test_5_approve_tiles_are_inert_until_armed() {
    openApproval()
    var once = tile("Approve once")
    var grant = tile("Approve 2m")
    verify(once !== null && grant !== null, "approve tiles not found")
    verify(!once.enabled && !grant.enabled, "approve tiles must be disabled while unarmed")
    // A click already on its way when the card appears.
    mouseClick(once)
    mouseClick(grant)
    compare(tc.calls.join(","), "", "a click reached an approve tile before arming")
    tryVerify(function() { return tc.screen.armed }, 2000, "the card never armed")
    verify(once.enabled && grant.enabled, "approve tiles stay disabled after arming")
  }

  function test_6_keyboard_approval_still_works_once_armed() {
    openApproval()
    tryVerify(function() { return tc.screen.armed }, 2000, "the card never armed")
    keyClick(Qt.Key_Tab)
    keyClick(Qt.Key_Space)
    compare(tc.calls.join(","), "approve(0)", "Tab, Space must approve once the card is armed")
  }

  function test_7_escape_is_never_held_back() {
    openApproval()
    keyClick(Qt.Key_Escape)
    compare(tc.escapes, 1, "Escape must reach the deny handler even before arming")
  }

  function test_8_a_new_request_rearms() {
    openApproval()
    tryVerify(function() { return tc.screen.armed }, 2000, "the card never armed")
    approvalVault.sshPrompt = tc.prompt("deploy")
    verify(!tc.screen.armed, "the next request in the queue must start unarmed")
    keyClick(Qt.Key_Tab)
    keyClick(Qt.Key_Space)
    compare(tc.calls.join(","), "", "keys typed at the next request acted before it armed")
    tryVerify(function() { return tc.screen.armed }, 2000, "the card never re-armed")
    compare(focused(), tile("Deny"))
  }

  function test_9_unlock_field_waits_for_arming() {
    tc.screen = unlockComp.createObject(host)
    verify(tc.screen !== null, "the unlock screen did not build")
    tc.screen.focusDefault()
    keyClick(Qt.Key_A)
    keyClick(Qt.Key_B)
    keyClick(Qt.Key_Return)
    compare(unlockVault.masterPassword, "", "typing reached the password field before arming")
    compare(tc.calls.join(","), "", "Enter submitted before arming")
    tryVerify(function() { return tc.screen.armed }, 2000, "the unlock card never armed")
    tryVerify(function() {
      var f = focused()
      return f !== null && f.echoMode === TextInput.Password
    }, 1000, "the password field did not get focus once armed")
    keyClick(Qt.Key_X)
    compare(unlockVault.masterPassword, "x", "typing after arming must reach the field")
  }
}
