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

done()
