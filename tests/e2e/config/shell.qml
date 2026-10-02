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
    property var settings: ({ pinUnlock: true, fingerprintUnlock: false, fidoUnlock: false, rememberSession: Quickshell.env("QSBW_E2E_REMEMBER_SESSION") !== "0",
                              autoLockMinutes: 0, lockOnScreenLock: false, lockOnSuspend: false,
                              sshAgentEnabled: Quickshell.env("QSBW_E2E_SSH_AGENT") === "1" })
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
        clearPending: vault.allCredentialsClearPending,
        // What the shell itself holds: the vault helper keeps the rest.
        helper: vault.vaultHelperState, sessionHeld: vault.session === vault.heldSessionMarker,
        // Typed into pinentry, the shell never holds them: these stay empty.
        typed: [vault.masterPassword, vault.pinEntry, vault.pendingUnlockPassword].join("|"),
        pinentry: { available: vault.pinentryAvailable, found: vault.pinentryFound, declined: vault.pinentryDeclined,
                    active: vault.pinentryActive, notice: vault.pinentryNotice },
        // The open item's detail: whether it is the secret-free view, and
        // which fields are revealed.
        detail: vault.detailItem ? { name: vault.detailItem.name, withheld: vault.detailItem.secretsWithheld === true } : null,
        revealed: Object.keys(vault.revealedFields),
        passwords: vault.items.map(function(i) { return i.password }),
        hasPasswords: vault.items.map(function(i) { return i.hasPassword }),
        ssh: { phase: vault.sshAgentPhase, keys: vault.sshAgentKeyCount, prompt: vault.sshPrompt !== null, unlock: vault.sshUnlockRequest !== null,
               screenChecked: vault.screenLockCheckedAt > 0 }
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
    // The unlock screen's action, as the button runs it: pinentry takes the typing.
    function unlockPinentry(): void { vault.unlockWithPinentry() }
    function pinUnlockPinentry(): void { vault.unlockPinWithPinentry() }
    // "Type it here instead", after pinentry failed.
    function declinePinentry(): void { vault.declinePinentry() }
    function addAccount(): void { vault.beginAddAccount() }
    function cancelAdd(): void { vault.cancelAddAccount() }
    function switchTo(email: string): string {
      var rows = vault.accountRows
      for (var i = 0; i < rows.length; i++) if (rows[i].email === email) { vault.switchAccount(rows[i].slot); return "ok" }
      return "unknown"
    }
    function logout(): void { vault.logoutAccount() }
    function copyFirst(): void { vault.copyPassword(vault.items[0]) }
    function openFirst(): void { vault.openDetail(vault.items[0]) }
    function reveal(key: string): void { vault.toggleFieldReveal(key) }
    function copyField(key: string): void { vault.copyDetailField(key, key) }
    function approveSsh(seconds: int): void { vault.approveSshRequest(seconds) }
    // A `bw status` check, as waking from sleep runs with the panel open.
    function refresh(): void { vault.refreshStatus() }
  }
}
