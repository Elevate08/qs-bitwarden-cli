import QtQuick
import Quickshell
import Quickshell.Io
// `plugin` is a link to the checkout, made by accounts.e2e.js in its own
// temporary copy of this directory.
import "plugin" as Plugin

// The vault service, headless, behind a stand-in view and a test-only IPC
// target. Never loaded by a real shell: the plugin's entry points are
// Panel.qml and Service.qml, and this file is neither.
ShellRoot {
  QtObject {
    id: view
    property bool opened: false
    property string screenName: "TEST-1"
    property var settings: ({ pinUnlock: true, fingerprintUnlock: false, fidoUnlock: false, rememberSession: true,
                              autoLockMinutes: 0, lockOnScreenLock: false, lockOnSuspend: false })
    function showPopout() { opened = true }
    function hidePopout() { opened = false }
    function focusField(name) {}
    function fieldHasFocus(name) { return false }
    function loginFieldHasFocus() { return false }
    function unlockFieldHasFocus() { return false }
    function syncLoginFields() {}
    function syncSensitiveFields() {}
    function revealListIndex(index) {}
    function updateSettingsSticky() {}
  }

  Plugin.Service {
    id: vault
    Component.onCompleted: attachView(view)
  }

  IpcHandler {
    target: "qsbwtest"
    function state(): string {
      return JSON.stringify({
        status: vault.status, screen: vault.currentScreen, slot: vault.activeSlot,
        email: vault.userEmail, accountId: vault.accountId, adding: vault.addingAccount,
        accounts: vault.accountRows, items: vault.items.map(function(i) { return i.name }),
        pinConfigured: vault.pinConfigured, pinReady: vault.pinReady,
        envelope: vault.envelopeSummary ? { pin: !!vault.envelopeSummary.pin, account: vault.envelopeSummary.account } : null,
        quick: vault.quickUnlockAvailable, error: vault.errorMessage, pinError: vault.pinError,
        pinUnlockError: vault.pinUnlockError, logoutPending: vault.logoutPending, opened: vault.opened,
        logoutCliDone: vault.logoutCliDone, logoutCredentialsDone: vault.logoutCredentialsDone,
        clearPending: vault.allCredentialsClearPending
      })
    }
    function open(): void { vault.open() }
    function login(email: string, pw: string): void {
      vault.loginMethod = "email"; vault.loginEmail = email; vault.loginPassword = pw; vault.submitLogin()
    }
    function unlock(pw: string): void { vault.masterPassword = pw; vault.unlockVault() }
    function lock(): void { vault.lockVault() }
    function setPin(pin: string, pw: string): void {
      vault.beginPinSetup(); vault.pinSetupPin = pin; vault.pinSetupConfirm = pin; vault.pinSetupMaster = pw; vault.submitPinSetup()
    }
    function pinUnlock(pin: string): void { vault.pinEntry = pin; vault.submitPinUnlock() }
    function addAccount(): void { vault.beginAddAccount() }
    function cancelAdd(): void { vault.cancelAddAccount() }
    function switchTo(email: string): string {
      var rows = vault.accountRows
      for (var i = 0; i < rows.length; i++) if (rows[i].email === email) { vault.switchAccount(rows[i].slot); return "ok" }
      return "unknown"
    }
    function logout(): void { vault.logoutAccount() }
  }
}
