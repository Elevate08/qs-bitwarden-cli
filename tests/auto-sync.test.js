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
  "beginEpochOperation", "epochOperationIsStale", "loadItems", "abandonSyncReload"]
const deps = Model.parseDependencies("bw=1\njq=1\nomarchy=1", null, {})
const noJq = Model.parseDependencies("bw=1\njq=0\nomarchy=1", null, {})

function fixture() {
  const c = {
    now: 1000000, live: true, session: "test-session", status: "unlocked",
    opened: true, pinentryActive: false, currentScreen: "main", autoSyncMinutes: 5, lastSyncAttemptAt: 0,
    isLoading: false, isUnlocking: false, logoutPending: false,
    metadataLoadPending: false, creatingFolder: false, repromptBusy: false,
    sendBusy: false, sshTotalPendingCount: 0, isSyncing: false,
    autoLockMinutes: 15, autoLockArmedAt: 1000000, suspendLockPending: false, syncReloadPending: false,
    autoSyncReloadPending: false, backgroundSync: false,
    autoSyncError: "Automatic sync failed. The local vault may be out of date.",
    errorMessage: "", vaultEpoch: 1, readEpochs: {}, itemsLoadedAt: 100,
    statusRefreshAfterItems: false, loadCalls: [], flashes: [], closedFilters: 0,
    dependencies: deps, listReadEarly: false, listReadMode: "", listReads: 0,
    Model, authAttemptInFlight: () => false,
    beginInitialVaultLoad: (spinner, metadata) => c.loadCalls.push([spinner, metadata]),
    startVaultListRead: () => { c.listReads += 1; c.listProc.running = true },
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
eq("automatic sync defaults to every 15 minutes", Model.intSetting("autoSyncMinutes", undefined), 15)
eq("schema exposes General setting", schema.group, "general")
for (const value of [null, false, "invalid", -1, Infinity])
  eq(`invalid interval ${value} falls back to the default`, Model.intSetting("autoSyncMinutes", value), 15)
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
for (const screen of ["detail", "edit", "settings", "generator", "sends", "accounts"]) {
  // Closing on a copy from an item leaves the screen behind; opening an
  // unlocked panel goes back to the list anyway.
  const c = fixture(); c.opened = false; c.currentScreen = screen; c.maybeAutoSync()
  eq(`a closed panel left on ${screen} still syncs`, c.syncProc.running, true)
}
{
  const c = fixture(); c.opened = false; c.currentScreen = "edit"; c.pinentryActive = true
  c.maybeAutoSync()
  eq("defer while pinentry hides the panel, which returns to its screen", c.syncProc.running, false)
}
{
  const c = fixture(); c.maybeAutoSync(); c.currentScreen = "edit"; c.finish(0)
  eq("an open edit form defers the reload", c.loadCalls.length, 0)
  c.opened = false; c.maybeAutoSync()
  eq("closing the panel releases it", c.loadCalls.length, 1)
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
  // Resumed with lockOnSuspend off: the watchdog locks on its next poll.
  const c = fixture(); c.now = c.autoLockArmedAt + 15 * 60 * 1000; c.maybeAutoSync()
  eq("no sync for a vault past its auto-lock deadline", c.syncProc.running, false)
  c.now -= 1; c.maybeAutoSync()
  eq("a vault inside its deadline syncs", c.syncProc.running, true)
  eq("the sync leaves the deadline where it was", c.autoLockArmedAt, 1000000)
}
{
  const c = fixture(); c.autoLockMinutes = 0; c.now += 24 * 3600 * 1000; c.maybeAutoSync()
  eq("auto-lock off never blocks a sync", c.syncProc.running, true)
}
{
  const c = fixture(); c.suspendLockPending = true; c.maybeAutoSync()
  eq("no sync while locking for a suspend", c.syncProc.running, false)
}
{
  // A key load fails every signing request the SSH agent holds for approval.
  const c = fixture(); c.sshTotalPendingCount = 1; c.maybeAutoSync()
  eq("defer while an SSH request waits for approval", c.syncProc.running, false)
  c.sshTotalPendingCount = 0; c.maybeAutoSync(); c.sshTotalPendingCount = 1; c.finish(0)
  eq("an SSH request arriving during the sync defers the list reload", c.loadCalls.length, 0)
  c.sshTotalPendingCount = 0; c.maybeAutoSync()
  eq("the reload runs once the request is answered", c.loadCalls.length, 1)
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
  // The user asks while an automatic sync is in flight: it is theirs now.
  const c = fixture(); c.maybeAutoSync(); c.syncVault()
  eq("a manual request does not start a second sync", c.lastSyncAttemptAt, c.now)
  eq("it closes the filter drawer like a manual sync", c.closedFilters, 1)
  c.finish(0)
  eq("its reload shows the spinner", JSON.stringify(c.loadCalls), "[[true,true]]")
  c.beginVaultRead("items"); c.onListFinished("[]")
  eq("and reports success", JSON.stringify(c.flashes), JSON.stringify(["Vault synced with Bitwarden"]))
}
{
  const c = fixture(); c.errorMessage = "An unrelated edit failed"
  c.maybeAutoSync(); c.syncVault(); c.finish(1)
  eq("a taken-over failure says so like a manual one", c.errorMessage, "Sync failed")
}
{
  // Asked for during the reload an automatic sync owed.
  const c = fixture(); c.maybeAutoSync(); c.currentScreen = "edit"; c.finish(0)
  c.currentScreen = "main"; c.maybeAutoSync(); c.syncVault()
  eq("no second sync during the reload", c.syncProc.running, false)
  c.beginVaultRead("items"); c.onListFinished("[]")
  eq("the reload reports success", c.flashes.length, 1)
}
{
  // Auto-lock off, or an hour's suspend would have locked the vault.
  const c = fixture(); c.autoLockMinutes = 0
  c.maybeAutoSync(); c.finish(1); c.now += 3600000; c.maybeAutoSync()
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
{
  // The list read is blocked (jq gone): the reload a sync ends with cannot
  // run, and used to leave "syncing" set until a lock.
  const c = fixture(); c.dependencies = noJq; c.maybeAutoSync()
  eq("no automatic sync while the list read is blocked", c.syncProc.running, false)
  const reloads = x => { x.beginInitialVaultLoad = spinner => x.loadItems(spinner) }
  // The read goes blocked while a background sync runs: its reload is held
  // (not stranded as "syncing"), and runs once the read can.
  const d = fixture(); reloads(d); d.maybeAutoSync(); d.dependencies = noJq; d.finish(0)
  check("a background sync finishing with the read blocked holds its reload",
    !d.isSyncing && !d.syncReloadPending && d.autoSyncReloadPending && d.listReads === 0,
    JSON.stringify({ isSyncing: d.isSyncing, reload: d.syncReloadPending, held: d.autoSyncReloadPending }))
  d.dependencies = noJq; d.now += 300000; d.maybeAutoSync()
  eq("and no new sync starts behind it meanwhile", d.syncProc.running, false)
  d.dependencies = deps; d.maybeAutoSync()
  check("the held reload runs once the read can", d.listReads === 1 && d.isSyncing && d.syncReloadPending, "")
  d.onListFinished("[]")
  check("and completes the sync", !d.isSyncing && !d.syncReloadPending && !d.backgroundSync, "")
  // A manual sync's reload is not held back by the idle check; blocked, it
  // used to leave "syncing" set until a lock.
  const m = fixture(); reloads(m); m.syncVault(); m.dependencies = noJq; m.finish(0)
  check("a manual sync whose reload is blocked is over, not stranded",
    !m.isSyncing && !m.syncReloadPending && !m.backgroundSync && m.listReads === 0,
    JSON.stringify({ isSyncing: m.isSyncing, reload: m.syncReloadPending }))
  eq("and the blocked read says why", m.errorMessage, Model.vaultListBlockedMessage(noJq))
  m.dependencies = deps; m.now += 300000; m.maybeAutoSync()
  eq("the next automatic sync is not stuck behind it", m.syncProc.running, true)
  const t = fixture(); t.isSyncing = true; t.syncReloadPending = true; t.session = ""; t.loadItems(false)
  check("a reload that finds no session is over too", !t.isSyncing && !t.syncReloadPending, "")
  const p = fixture(); p.isSyncing = true; p.dependencies = noJq; p.loadItems(true)
  check("a plain load owes no sync and leaves one in flight alone", p.isSyncing && !p.isLoading, "")
  check("a failed list read releases the background flag with the sync guard",
    /isSyncing = false\s*syncReloadPending = false\s*backgroundSync = false/.test(functionBody(source, "onListProcessExited")),
    functionBody(source, "onListProcessExited"))
}
check("timer belongs to the shared service", /id: autoSyncTimer/.test(source)
  && !/id: autoSyncTimer/.test(read("Panel.qml")), "one timer across monitors")
check("timer stops while locked and can finish a pending reload", /running: root.live && root.status === "unlocked" && root.session !== ""\s*&& \(root.autoSyncMinutes > 0 \|\| root.autoSyncReloadPending\)/.test(source), "timer guard missing")
for (const name of ["maybeAutoSync", "syncVault", "onSyncFinished"])
  check(`${name} never extends the lock deadline`, !/resetAutoLockTimer|autoLockArmedAt\s*=/.test(functionBody(source, name)), name)
// A background sync that succeeds says nothing: the header and the sync
// button show only a sync the user asked for, and the button stays usable so a
// click during a background sync can take it over (syncVault()).
const panel = read("Panel.qml")
check("the panel shows only a user's sync",
  /readonly property bool userSyncing: root\.vault\.isSyncing && !root\.vault\.backgroundSync/.test(panel)
    && /if \(root\.userSyncing\) return "Syncing\.\.\."/.test(panel)
    && /tooltipText: root\.userSyncing \? "Syncing\.\.\." : "Sync vault \(r\)"/.test(panel)
    && /enabled: !root\.userSyncing/.test(panel),
  "header text, tooltip and enabled must go through userSyncing")
check("and reaches isSyncing nowhere else",
  (panel.match(/\bisSyncing\b/g) || []).length === 1, String((panel.match(/\bisSyncing\b/g) || []).length))
{
  const c = fixture(); c.autoSyncMinutes = 5; c.now += 400000; c.maybeAutoSync()
  check("a background sync is not a user's", c.isSyncing && c.backgroundSync, "")
  c.syncVault()
  check("asking during it makes it one, reported like any other", c.isSyncing && !c.backgroundSync && c.syncProc.running, "")
}
done()
