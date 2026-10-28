#!/usr/bin/env node
// Exercise the service's actual scheduling/completion code with a fake clock
// and CLI, including an offline server returning, edits and stale sessions.
const vm = require("vm")
const { createSuite, functionBody, loadModule, read } = require("./harness")
const { check, eq, done } = createSuite("auto-sync")
const Model = loadModule()
const source = read("Service.qml")
const functions = ["autoSyncIdle", "maybeAutoSync", "syncVault", "onSyncFinished",
  "onListFinished", "dropVaultState", "beginVaultRead", "vaultReadIsStale",
  "beginEpochOperation", "epochOperationIsStale"]

function fixture() {
  const c = {
    now: 1000000, live: true, session: "test-session", status: "unlocked",
    currentScreen: "main", autoSyncMinutes: 5, lastSyncAttemptAt: 0,
    isLoading: false, isUnlocking: false, logoutPending: false,
    metadataLoadPending: false, creatingFolder: false, repromptBusy: false,
    sendBusy: false, isSyncing: false, syncReloadPending: false,
    autoSyncReloadPending: false, backgroundSync: false,
    autoSyncError: "Automatic sync failed. The local vault may be out of date.",
    errorMessage: "", vaultEpoch: 1, readEpochs: {}, itemsLoadedAt: 100,
    statusRefreshAfterItems: false, loadCalls: [], flashes: [], closedFilters: 0,
    Model, authAttemptInFlight: () => false,
    beginInitialVaultLoad: (spinner, metadata) => c.loadCalls.push([spinner, metadata]),
    closeFilterGroup: () => c.closedFilters++,
    flashNotification: message => c.flashes.push(message),
    refreshDerivedFromItems() {}, maybeStartupLoad() {},
    deferredMetadataTimer: { restart() {} }
  }
  for (const proc of ["listProc", "listOrgsProc", "listFoldersProc", "createItemProc",
    "editItemProc", "deleteItemProc", "createFolderProc", "syncProc"])
    c[proc] = { running: false, command: [] }
  for (const name of ["cancelEnvelopeUnlockJobs", "cancelPinentry", "resetPinentryChoice",
    "cancelFingerprintUnlock", "cancelFidoUnlock", "cancelAttachmentDownloads",
    "forgetVault", "resetItemForm", "dropVaultSecrets"]) c[name] = () => {}
  c.Date = { now: () => c.now }
  vm.createContext(c)
  vm.runInContext(functions.map(n => functionBody(source, n)).join("\n"), c)
  c.finish = code => { c.syncProc.running = false; c.onSyncFinished(code) }
  return c
}

const schema = Model.settingSchemaEntry("autoSyncMinutes")
eq("automatic sync is opt-in", Model.intSetting("autoSyncMinutes", undefined), 0)
eq("schema exposes General setting", schema.group, "general")
for (const value of [null, false, "invalid", -1, Infinity])
  eq(`invalid interval ${value} disables scheduling`, Model.intSetting("autoSyncMinutes", value), 0)
eq("large interval is bounded", Model.intSetting("autoSyncMinutes", 1e12), 1440)
eq("a one-minute interval is supported", Model.intSetting("autoSyncMinutes", 1), 1)
{
  const c = fixture(); c.autoSyncMinutes = 0; c.maybeAutoSync()
  eq("disabled does no network work", c.syncProc.running, false)
}
for (const [key, value] of [["live", false], ["session", ""], ["status", "locked"],
  ["currentScreen", "edit"], ["currentScreen", "detail"], ["currentScreen", "settings"],
  ["isLoading", true], ["isUnlocking", true], ["logoutPending", true],
  ["metadataLoadPending", true], ["creatingFolder", true], ["repromptBusy", true],
  ["sendBusy", true], ["isSyncing", true]]) {
  const c = fixture(); c[key] = value; c.maybeAutoSync()
  eq(`defer while ${key}=${value}`, c.syncProc.running, false)
}
for (const proc of ["listProc", "listOrgsProc", "listFoldersProc", "createItemProc",
  "editItemProc", "deleteItemProc", "createFolderProc", "syncProc"]) {
  const c = fixture(); c[proc].running = true; c.maybeAutoSync()
  eq(`do not start beside ${proc}`, c.lastSyncAttemptAt, 0)
}
{
  const c = fixture(); c.authAttemptInFlight = () => true; c.maybeAutoSync()
  eq("defer during authentication", c.syncProc.running, false)
}
{
  const c = fixture(); c.maybeAutoSync()
  eq("first unlocked idle tick starts sync", c.syncProc.running, true)
  eq("background sync leaves the filter drawer alone", c.closedFilters, 0)
  eq("uses the existing bounded CLI command", JSON.stringify(c.syncProc.command), JSON.stringify(Model.syncCommand()))
  const started = c.lastSyncAttemptAt
  c.now += 30000; c.maybeAutoSync()
  eq("a second tick cannot replace an in-flight sync", c.lastSyncAttemptAt, started)
  c.finish(1)
  eq("offline failure preserves the local item timestamp", c.itemsLoadedAt, 100)
  eq("offline failure does not reload the vault", c.loadCalls.length, 0)
  eq("offline failure is visible", c.errorMessage, c.autoSyncError)
  c.now = started + 299999; c.maybeAutoSync()
  eq("no busy retry loop while offline", c.syncProc.running, false)
  c.now = started + 300000; c.maybeAutoSync()
  eq("retry is due at the configured interval", c.syncProc.running, true)
  c.finish(0)
  eq("recovery clears its own failure", c.errorMessage, "")
  eq("recovery reloads without a foreground spinner", JSON.stringify(c.loadCalls), "[[false,true]]")
  c.beginVaultRead("items"); c.onListFinished("[]")
  eq("background success does not flash a notification", c.flashes.length, 0)
  eq("completion releases the sync guard", c.isSyncing, false)
}
{
  const c = fixture(); c.errorMessage = "An unrelated edit failed"
  c.maybeAutoSync(); c.finish(1)
  eq("background failure preserves unrelated errors", c.errorMessage, "An unrelated edit failed")
  c.now += 300000; c.maybeAutoSync(); c.finish(0)
  eq("background recovery preserves unrelated errors", c.errorMessage, "An unrelated edit failed")
}
{
  const c = fixture(); c.maybeAutoSync(); c.currentScreen = "edit"; c.finish(0)
  eq("finishing during an edit defers the list reload", c.loadCalls.length, 0)
  eq("the pending reload is remembered", c.autoSyncReloadPending, true)
  c.autoSyncMinutes = 0; c.maybeAutoSync()
  eq("disabled setting does not interrupt the edit", c.loadCalls.length, 0)
  c.currentScreen = "main"; c.maybeAutoSync()
  eq("finish the already successful sync after returning, even when disabled", c.loadCalls.length, 1)
}
{
  const c = fixture(); c.syncVault()
  eq("manual sync still closes filters", c.closedFilters, 1)
  c.finish(0); c.beginVaultRead("items"); c.onListFinished("[]")
  eq("manual sync still reports success", c.flashes.length, 1)
  c.now += 299999; c.maybeAutoSync()
  eq("manual sync delays the next automatic attempt", c.syncProc.running, false)
}
{
  const c = fixture(); c.maybeAutoSync(); c.finish(1); c.now += 3600000; c.maybeAutoSync()
  eq("catch up after suspend", c.syncProc.running, true)
  c.finish(1); c.now -= 7200000; c.maybeAutoSync()
  eq("a backwards clock does not freeze retries", c.syncProc.running, true)
}
for (const code of [0, 1]) {
  const c = fixture(); c.maybeAutoSync(); c.dropVaultState()
  c.session = "new-account-session"; c.status = "unlocked"
  c.maybeAutoSync()
  eq("old in-flight command cannot have its epoch overwritten", c.lastSyncAttemptAt, 0)
  c.finish(code)
  eq(`late exit ${code} cannot reload another account`, c.loadCalls.length, 0)
  eq(`late exit ${code} cannot set another account's error`, c.errorMessage, "")
  c.maybeAutoSync()
  eq("new account gets its own first sync", c.readEpochs.sync, c.vaultEpoch)
}
{
  const c = fixture(); c.maybeAutoSync(); c.currentScreen = "edit"; c.finish(0)
  c.dropVaultState()
  eq("locking drops a deferred reload", c.autoSyncReloadPending, false)
  eq("locking clears the background flag", c.backgroundSync, false)
}
check("timer belongs to the shared service", /id: autoSyncTimer/.test(source)
  && !/id: autoSyncTimer/.test(read("Panel.qml")), "one timer across monitors")
check("timer stops while locked and can finish a pending reload", /running: root.live && root.status === "unlocked" && root.session !== ""\s*&& \(root.autoSyncMinutes > 0 \|\| root.autoSyncReloadPending\)/.test(source), "timer guard missing")
for (const name of ["maybeAutoSync", "syncVault", "onSyncFinished"])
  check(`${name} never extends the lock deadline`, !/resetAutoLockTimer|autoLockArmedAt\s*=/.test(functionBody(source, name)), name)
done()
