#!/usr/bin/env node
// A background status refresh after helper loss must not erase why the vault
// locked. Run the real refresh callbacks with a stale probe queued at lock.
const { createSuite, functionBody, loadModule, read } = require("./harness")
const { eq, done } = createSuite("helper-loss-notice")
const Model = loadModule()
const service = read("Service.qml")
const notice = /readonly property string vaultHelperLostMessage: "([^"]+)"/.exec(service)[1]

function vault(errorMessage) {
  const later = []
  const v = {
    Model, Qt: { callLater: f => later.push(f) },
    autoSyncError: /readonly property string autoSyncError: "([^"]+)"/.exec(service)[1],
    errorMessage, status: "locked", logoutPending: false,
    depsChecked: true, setupGated: false, accountsLoaded: true,
    statusRefreshPending: true, statusCheckQueued: false,
    statusProbeStarted: true, terminalLoginStartedAt: 0,
    vaultHelperLostMessage: notice, probes: 0,
    sessionHandoffProc: { running: false },
    beginEpochOperation() { this.probes++ },
    epochOperationIsStale() { return true }
  }
  for (const name of ["refreshStatus", "restartStaleStatusProbe", "onStatusFinished"]) {
    v[name] = new Function("scope", "with(scope){" + functionBody(service, name) + "\nreturn " + name + "}")(v)
  }
  v.settle = () => { while (later.length) later.shift()() }
  return v
}

{
  const v = vault(notice)
  // A probe that was running when the helper died now belongs to the old
  // vault epoch. Its exit schedules a refresh after the lock notice was set.
  v.onStatusFinished("")
  v.settle()
  eq("a stale probe refreshes once after the helper died", v.probes, 1)
  eq("the refresh preserves the explanation for the lock", v.errorMessage, notice)
  eq("the vault stays locked", v.status, "locked")
}
{
  const v = vault(notice)
  v.refreshStatus()
  eq("a background refresh also preserves the helper-loss notice", v.errorMessage, notice)
}
{
  const v = vault("An earlier operation failed")
  v.refreshStatus()
  eq("a refresh still clears an ordinary operation error", v.errorMessage, "")
}
{
  // A terminal login inside its handoff window unlocks the vault on the next
  // wake refresh; the old lock reason must not outlive that unlock.
  const v = vault(notice)
  for (const name of ["cancelAuthPrewarm", "abandonAuthSecrets", "storeCurrentSession",
    "beginInitialVaultLoad", "resetAutoLockTimer", "focusAppropriateField"]) v[name] = () => {}
  v.flashNotification = text => { v.flash = text }
  v.epochOperationIsStale = () => false
  v.vaultEpoch = 0
  v.terminalLoginStartedAt = Date.now()
  v.onSessionHandoff = new Function("scope", "with(scope){" + functionBody(service, "onSessionHandoff") +
    "\nreturn onSessionHandoff}")(v)
  v.onSessionHandoff("a".repeat(88))
  eq("the handed-over session unlocks the vault", v.status, "unlocked")
  eq("the handoff clears the helper-loss notice", v.errorMessage, "")
  eq("so the terminal sign-in flash can show", v.flash, "Signed in from the terminal")
}

{
  const v = vault("")
  v.errorMessage = v.autoSyncError
  v.refreshStatus()
  eq("opening the panel preserves a background sync failure", v.errorMessage, v.autoSyncError)
}

done()
