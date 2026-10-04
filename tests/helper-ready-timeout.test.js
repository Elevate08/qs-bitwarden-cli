#!/usr/bin/env node
// Virtual time drives the actual startup functions; a baseline with no
// deadline keeps waiting and fails on state, without requiring any new API.
const { createSuite, functionBody } = require("./harness")
const fs = require("fs")
const path = require("path")
const sourceRoot = process.env.REVIEW_SOURCE_ROOT || path.join(__dirname, "..")
const service = fs.readFileSync(path.join(sourceRoot, "Service.qml"), "utf8")
const model = fs.readFileSync(path.join(sourceRoot, "BitwardenModel.js"), "utf8").replace(/^\.pragma library\s*$/m, "")
const exportsList = [...model.matchAll(/^(?:function\s+(\w+)|var\s+(\w+))/gm)].map(m => m[1] || m[2])
const Model = new Function(model + "\nreturn {" + exportsList.join(",") + "}")()
const { eq, check, done } = createSuite("helper-ready-timeout")
function vault() {
  const v = {
    Model, console: { warn() {} }, Qt: { callLater: f => f() },
    vaultHelperState: "pending", vaultHelper: { source: "bundled" }, sshAgentPluginDir: "/synthetic/plugin",
    vaultHelperRestarts: 2, vaultHelperWarning: "", shuttingDown: false, allowVaultWithoutHelper: true,
    vaultHelperReadyTimedOut: false, vaultHelperRetryPending: false,
    vaultRuns: {}, vaultQueries: {}, session: "", heldSessionMarker: Model.vaultHeldSession(),
    vaultHelperMaxRestarts: 3, inspections: 0, flushed: 0,
    vaultHelperProc: { running: false, pid: 123, writes: [], write(value) { this.writes.push(value) } },
    vaultHelperSettleTimer: { restart() {}, stop() {} },
    vaultHelperReadyTimer: { armed: false, restart() { this.armed = true }, stop() { this.armed = false } },
    inspectVaultHelper() { this.inspections++ }, flushVaultWaiting() { this.flushed++ },
    useVaultFallback() { this.vaultHelperState = "fallback" }
  }
  v.root = v
  for (const n of ["startVaultHelper", "onVaultHelperStarted", "onVaultHelperLine", "onVaultHelperExited",
    "retryVaultHelper", "stopVaultHelper", "onVaultHelperReadyTimeout"]) {
    const body = functionBody(service, n)
    if (body) v[n] = new Function("scope", "with(scope){" + body + "\nreturn " + n + "}")(v)
  }
  // Only an actually armed production timer can fire; baseline has none.
  v.advanceDeadline = () => {
    if (v.vaultHelperReadyTimer.armed) {
      v.vaultHelperReadyTimer.armed = false
      v.onVaultHelperReadyTimeout()
    }
  }
  return v
}
const ready = JSON.stringify({ type: "ready" })
{
  const v = vault(); v.startVaultHelper(); v.onVaultHelperStarted()
  eq("startup sends hello", v.vaultHelperProc.writes.length, 1)
  v.advanceDeadline()
  eq("silent helper reaches stopped by its deadline", v.vaultHelperState, "stopped")
  eq("timeout terminates helper", v.vaultHelperProc.running, false)
  check("timeout surfaces a retry notice", /did not answer|timed out/i.test(v.vaultHelperWarning), v.vaultHelperWarning)
  eq("no waiting secret jobs are flushed on timeout", v.flushed, 0)
  v.onVaultHelperLine(ready)
  eq("late ready cannot reopen the timed-out helper", v.vaultHelperState, "stopped")
  v.retryVaultHelper()
  eq("retry waits for old helper exit", v.inspections, 0)
  v.vaultHelperProc.pid = 0
  v.onVaultHelperExited(15)
  eq("old exit starts one requested retry", v.inspections, 1)
  eq("retry returns to inspection", v.vaultHelperState, "pending")
  eq("retry resets restart allowance", v.vaultHelperRestarts, 0)
  v.startVaultHelper(); v.onVaultHelperStarted(); v.onVaultHelperLine(ready)
  v.advanceDeadline()
  eq("a successful retry stays active past the deadline", v.vaultHelperState, "active")
  eq("waiting jobs flush only after readiness", v.flushed, 1)
}
{
  const v = vault(); v.startVaultHelper(); v.advanceDeadline()
  v.vaultHelperProc.pid = 0; v.onVaultHelperExited(15)
  eq("timeout exit does not automatically restart", v.vaultHelperState, "stopped")
  eq("timeout never selects allowed fallback", v.flushed, 0)
  v.retryVaultHelper()
  eq("retry after exit inspects once", v.inspections, 1)
}
done()
