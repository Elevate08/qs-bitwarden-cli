#!/usr/bin/env node
// The shared reader processes (VaultProcess) run one command at a time:
// setting `running` on one that is still running starts nothing, and the
// answer that arrives next is the earlier run's. The service's own functions
// run here against stand-in processes that behave that way, so a read asked
// for while its process is held (an account just left, a lock's scrub, a
// killed run whose exit is still to come, an older refresh) must wait for
// that run, and that run's answer must never be taken for the new read's.
//
//   node tests/list-races.test.js

const vm = require("vm")
const { createSuite, functionBody, loadModule, read } = require("./harness")
const { check, eq, done } = createSuite("list-races")
const Model = loadModule()
const source = read("Service.qml")

const functions = ["beginEpochOperation", "invalidateEpochOperation", "beginVaultRead", "vaultReadIsStale",
  "vaultProcBusy", "vaultReadRunning", "startVaultRead", "supersededVaultRead", "finishScrubRun",
  "loadItems", "abandonSyncReload", "startVaultListRead", "vaultListEnv", "onListFinished", "onListProcessExited",
  "loadOrganizations", "onListOrgsFinished", "loadFolders", "onListFoldersFinished",
  "loadOrgCollections", "onOrgCollectionsLoaded", "loadSends", "onSendsLoaded",
  "openDetail", "onDetailFinished", "itemNeedsReprompt", "dropVaultState", "listSnapshotOutdated",
  "settleOwedListRead", "onSaveItemFinished", "followCreatedItem", "resumeCreatedItem", "leaveProvisionalDetail",
  "onDeleteItemFinished", "reconcileOpenDetail", "totpWanted",
  "isFieldRevealed", "itemChangeRunning"]

// VaultProcess, as far as starting goes: a change of `running` to true starts
// a run only when none is held (runId 0); to false it asks for a kill, and
// the run stays held until its exit arrives (exit()).
function makeProc(name, runs) {
  const p = {
    name, command: [], environment: {}, runId: 0, value: false,
    get running() { return this.value },
    set running(v) {
      v = Boolean(v)
      if (v === this.value) return
      this.value = v
      if (v && this.runId === 0) {
        this.runId = runs.length + 1
        runs.push({ proc: name, command: this.command })
      }
    },
    // VaultProcess.finish(): the run is over before exited() is emitted.
    end() { this.runId = 0; this.value = false }
  }
  return p
}

// The body of `onExited: function(exitCode) { ... }` of the process `id`.
function exitHandler(id) {
  const at = source.indexOf(`id: ${id}\n`)
  const start = source.indexOf("onExited: function(exitCode) {", at)
  let depth = 0
  for (let i = source.indexOf("{", start); i < source.length; i++) {
    if (source[i] === "{") depth++
    else if (source[i] === "}" && --depth === 0) return source.slice(source.indexOf("{", start) + 1, i)
  }
  return ""
}

const deps = Model.parseDependencies("bw=1\njq=1\nomarchy=1", null, {})
const READERS = [
  ["organizations", "listOrgsProc", "listOrgsStdout", "loadOrganizations"],
  ["folders", "listFoldersProc", "listFoldersStdout", "loadFolders"],
  ["sends", "listSendsProc", "listSendsStdout", "loadSends"]
]

function fixture() {
  const runs = []
  const c = {
    Model, runs, console,
    session: "session-a", status: "unlocked", vaultEpoch: 1, readEpochs: {}, queuedReads: {},
    vaultChanges: 0, listReadChanges: 0, listRereadOwed: false, createdItemHandoff: null,
    pendingSave: null, pendingDelete: null, recheckArmedAutoType() {}, recheckTotpFollowup() {},
    vaultHelperActive: true, dependencies: deps,
    items: [], filteredItems: [], organizations: [], folders: [], sends: [], sendIndex: 0,
    itemsLoadedAt: 0, orgsLoadedAt: 0, foldersLoadedAt: 0, metaFreshMs: 0,
    isLoading: false, isSyncing: false, syncReloadPending: false, backgroundSync: false,
    autoSyncReloadPending: false, metadataLoadPending: false, metadataForceRefresh: false,
    statusRefreshAfterItems: false, sendsLoading: false, formCollectionsLoading: false,
    formCollections: [], formCollectionIds: [],
    errorMessage: "", listReadError: "", autoSyncError: "auto", listReadMode: "", listReadEarly: false,
    listAgentBranchActive: false, listRetriedWithoutAgent: false, sshCapability: "",
    sshAgentGateOpen: false, sshAgentNextLoadId: "", sshAgentEpoch: 0, sshAgentLoadId: "",
    sshAgentLoadActive: false, sshAgentLoadedForVaultEpoch: -1, sshAgentProc: { stdinEnabled: false },
    scrubPending: [], scrubRetry: { stop() {}, restart() {} },
    detailItem: null, detailPassword: "", liveTotp: "", revealedFields: {}, showDeleteConfirm: false,
    attachmentQueue: [], attachmentSaved: {}, currentScreen: "main", repromptVerifiedId: "",
    flashes: [], derived: 0,
    bwEnv: () => ({}), endSshAgentLoad() {}, maybeStartupLoad() {}, deferredMetadataTimer: { restart() {} },
    refreshDerivedFromItems() { c.derived++ }, flashNotification: m => c.flashes.push(m),
    closeFilterGroup() {}, clearRepromptGrant() {}, learnFromPick() {}, fetchTotp() {},
    itemPayloadJson: "", failedSave: null, screenBeforeSshApproval: "main", forgotten: [],
    formIsEditing: false, formItemId: "", generatorReturnScreen: "main",
    forgetVaultItem: id => c.forgotten.push(id)
  }
  for (const id of ["listProc", "listOrgsProc", "listFoldersProc", "orgCollectionsProc", "listSendsProc", "getItemProc"])
    c[id] = makeProc(id, runs)
  for (const id of ["listStdout", "listStderr", "listOrgsStdout", "listFoldersStdout", "orgCollectionsStdout",
    "listSendsStdout", "getItemStdout", "getItemStderr"]) c[id] = { text: "" }
  for (const name of ["cancelEnvelopeUnlockJobs", "cancelPinentry", "resetPinentryChoice", "cancelFingerprintUnlock",
    "cancelFidoUnlock", "cancelAttachmentDownloads", "forgetVault", "resetItemForm", "dropVaultSecrets"]) c[name] = () => {}
  c.root = c
  vm.createContext(c)
  vm.runInContext(functions.map(n => functionBody(source, n)).join("\n"), c)
  for (const id of ["listProc", "listOrgsProc", "listFoldersProc", "orgCollectionsProc", "listSendsProc", "getItemProc"])
    vm.runInContext(`function exit_${id}(exitCode) {\n${exitHandler(id)}\n}`, c)
  // A run of `id` ends: its output is in the collectors, then exited().
  c.exit = (id, code, out, err) => {
    const stem = id.replace(/Proc$/, "")
    c[stem + "Stdout"].text = out || ""
    if (c[stem + "Stderr"]) c[stem + "Stderr"].text = err || ""
    c[id].end()
    c["exit_" + id](code)
  }
  // Lock, logout or account switch, then another vault opened.
  c.reopenAs = token => { c.dropVaultState(); c.session = token; c.status = "unlocked" }
  c.runsOf = id => runs.filter(r => r.proc === id)
  return c
}

const vaultOf = name => JSON.stringify({ sshCapability: "unconfirmed", sshKeys: [],
  items: [{ object: "item", id: "id-" + name, type: 1, name, login: { username: name } }] })
const names = c => Array.from(c.items).map(i => i.name).join()

// --- the item list across an account switch ----------------------------------------
{
  const c = fixture()
  c.loadItems(false)
  eq("a list read starts its command", c.runsOf("listProc").length, 1)
  const command = c.listProc.command
  c.reopenAs("session-b")
  // What the new account shows meanwhile: a message of its own, and no rows.
  c.errorMessage = "Could not safely read vault items."; c.listReadError = c.errorMessage
  c.loadItems(false)
  check("a read asked for while the old run is going starts no second command and leaves the run alone",
    c.runsOf("listProc").length === 1 && c.listProc.command === command, JSON.stringify(c.runs))
  check("the old run keeps the stamp of the vault it was started for, so it is stale",
    c.readEpochs.items !== c.vaultEpoch && c.vaultReadIsStale("items"), JSON.stringify(c.readEpochs))
  // The helper answers the obsolete run with exit 0 and nothing.
  c.exit("listProc", 0, "", "")
  check("the old run's empty answer is not the new account's list: its error stays and no list is accepted",
    c.errorMessage === "Could not safely read vault items." && c.listReadError === c.errorMessage
      && c.itemsLoadedAt === 0 && c.derived === 0, c.errorMessage + "|" + c.itemsLoadedAt)
  check("the waiting read starts once the old run has exited, stamped for the open vault",
    c.runsOf("listProc").length === 2 && c.listProc.running && c.readEpochs.items === c.vaultEpoch
      && !c.queuedReads.items, JSON.stringify(c.readEpochs))
  c.exit("listProc", 0, vaultOf("B"), "")
  check("and its answer is the new account's list", names(c) === "B" && c.errorMessage === "", names(c))
}
{
  // The same, with the old run answering with the old account's rows.
  const c = fixture()
  c.loadItems(false); c.reopenAs("session-b"); c.loadItems(false)
  c.exit("listProc", 0, vaultOf("A"), "")
  eq("the old account's rows are not drawn as the new account's", names(c), "")
  c.exit("listProc", 0, vaultOf("B"), "")
  eq("the new account's are", names(c), "B")
}
{
  // The old run fails: the failure is not the new read's either.
  const c = fixture()
  c.loadItems(false); c.reopenAs("session-b"); c.loadItems(true)
  c.exit("listProc", 1, "", "Vault is locked.")
  check("a failed old run shows no error and leaves the new read's spinner",
    c.errorMessage === "" && c.isLoading === true && c.runsOf("listProc").length === 2, c.errorMessage)
}

// --- a lock's scrub holds the process ------------------------------------------------
{
  const c = fixture()
  // scrubStep(): the idle process is borrowed to empty its collector.
  c.dropVaultState()
  c.listProc.command = Model.scrubCommand(); c.listProc.running = true; c.scrubPending = [c.listProc]
  c.session = "session-b"; c.status = "unlocked"
  c.loadItems(false)
  check("a read asked for during the scrub does not overwrite the scrub's command",
    Model.isScrubCommand(c.listProc.command) && c.runsOf("listProc").length === 1, JSON.stringify(c.listProc.command))
  c.exit("listProc", 0, "", "")
  check("the scrub's empty, zero-exit result is not read as an empty vault",
    c.itemsLoadedAt === 0 && c.derived === 0 && c.scrubPending.length === 0, String(c.itemsLoadedAt))
  check("and the read starts after it", c.runsOf("listProc").length === 2
    && !Model.isScrubCommand(c.listProc.command) && c.readEpochs.items === c.vaultEpoch, JSON.stringify(c.runs))
  c.exit("listProc", 0, vaultOf("B"), "")
  eq("with its own answer accepted", names(c), "B")
}

// --- a lock's scrub and a stopped run whose exit is still to come -----------------------
{
  const c = fixture()
  vm.runInContext(functionBody(source, "scrubStep"), c)
  c.loadItems(false)
  const command = c.listProc.command
  c.listStdout.text = "the old vault's list"
  c.listProc.running = false                    // cancelSshAgentLoad(): killed, its exit still to come
  c.dropVaultState()
  c.scrubPending = [c.listProc]
  c.scrubStep()
  check("the scrub leaves a stopped run's command alone until it has exited",
    c.listProc.command === command && c.scrubPending.length === 1 && c.runsOf("listProc").length === 1, JSON.stringify(c.listProc.command))
  c.exit("listProc", 143, "the old vault's list", "")
  check("that run's exit is not counted as the scrub", c.scrubPending.length === 1 && names(c) === "")
  c.scrubStep()                                 // scrubRetry
  check("the scrub then runs", Model.isScrubCommand(c.listProc.command) && c.runsOf("listProc").length === 2)
  c.exit("listProc", 0, "", "")
  eq("and is what clears the queue", c.scrubPending.length, 0)
}

// --- a killed run whose exit is still to come ---------------------------------------
{
  const c = fixture()
  c.loadItems(false)
  c.listProc.running = false          // cancelSshAgentLoad(): the kill is asked for
  check("premise: the process is still held", c.listProc.runId !== 0 && c.vaultProcBusy(c.listProc))
  c.loadItems(false)
  eq("a read asked for before the killed run has exited waits", c.runsOf("listProc").length, 1)
  c.exit("listProc", 143, "", "")
  check("the killed run's exit is not reported as this read's failure, and the read starts",
    c.errorMessage === "" && c.runsOf("listProc").length === 2 && c.listProc.running, c.errorMessage)
}

// --- within one vault, and what a lock drops ------------------------------------------
{
  // Asked again while a read of this vault is running (the panel opened, then
  // `bw status` answered): that read serves both, as it did.
  const c = fixture()
  c.loadItems(false); c.loadItems(false); c.loadItems(true)
  check("a second request during a read of the same vault starts nothing and waits for nothing",
    c.runsOf("listProc").length === 1 && !c.queuedReads.items, JSON.stringify(c.queuedReads))
  c.exit("listProc", 0, vaultOf("A"), "")
  check("and takes that read's answer", names(c) === "A" && c.runsOf("listProc").length === 1 && !c.listProc.running, names(c))
}
{
  // A sync finishes while a list read is going: that read is from before it.
  const c = fixture()
  c.syncProc = { running: false }; c.lastSyncAttemptAt = 0; c.maybeAutoSync = () => {}
  c.beginInitialVaultLoad = spinner => c.loadItems(spinner)
  vm.runInContext(functionBody(source, "onSyncFinished"), c)
  c.loadItems(false)
  c.isSyncing = true; c.readEpochs.sync = c.vaultEpoch
  c.onSyncFinished(0)
  check("the reload a sync ends with waits for a read that started before the sync finished",
    c.runsOf("listProc").length === 1 && !!c.queuedReads.items && c.syncReloadPending, JSON.stringify(c.queuedReads))
  c.exit("listProc", 0, vaultOf("before the sync"), "")
  check("the earlier snapshot is not shown as the synced vault; the reload replaces it",
    names(c) === "" && c.runsOf("listProc").length === 2 && c.syncReloadPending && c.flashes.length === 0, names(c))
  c.exit("listProc", 0, vaultOf("synced"), "")
  check("and nothing is left waiting", names(c) === "synced" && c.runsOf("listProc").length === 2 && !c.listProc.running
    && !c.syncReloadPending && c.flashes.indexOf("Vault synced with Bitwarden") !== -1, names(c))
}
{
  const c = fixture()
  c.loadItems(false); c.vaultChanges += 1; c.loadItems(false)
  check("premise: a read is waiting", !!c.queuedReads.items)
  c.dropVaultState()
  eq("dropping the vault drops every waiting read", JSON.stringify(c.queuedReads), "{}")
  c.exit("listProc", 0, vaultOf("A"), "")
  check("so nothing starts for a locked vault, and nothing is accepted",
    c.runsOf("listProc").length === 1 && names(c) === "" && !c.listProc.running, JSON.stringify(c.runs))
}
{
  // An early read (before `bw status` has confirmed the session) still serves a later request.
  const c = fixture()
  c.status = "checking"; c.loadItems(false); c.status = "unlocked"; c.loadItems(true)
  check("a confirmed load still rides the early read of the same vault",
    c.runsOf("listProc").length === 1 && !c.queuedReads.items, JSON.stringify(c.queuedReads))
  c.exit("listProc", 0, vaultOf("A"), "")
  eq("and takes its answer", names(c), "A")
}

// --- organizations, folders and Sends -------------------------------------------------
for (const [name, id, out, starter] of READERS) {
  const c = fixture()
  c[starter](true)
  c.reopenAs("session-b")
  c[starter](true)
  check(`${starter}(): asked again behind the old account's run, no second command and no new stamp`,
    c.runsOf(id).length === 1 && c.vaultReadIsStale(name), JSON.stringify(c.readEpochs))
  c.exit(id, 0, JSON.stringify([{ id: "x", name: "of the old account", object: "folder", type: 0, text: { text: "t" } }]), "")
  check(`${starter}(): the old run's answer is dropped and the waiting read starts`,
    c[name].length === 0 && c.runsOf(id).length === 2 && c.readEpochs[name] === c.vaultEpoch, JSON.stringify(c[name]))
  c.exit(id, 0, JSON.stringify([{ id: "y", name: "of the new account", object: "folder", type: 0, text: { text: "t" } }]), "")
  check(`${starter}(): the new run's answer is accepted`, c[name].length === 1 && c[name][0].id === "y", JSON.stringify(c[name]))
  if (name !== "sends") {
    c[starter](true); c[starter](false)
    check(`${starter}(): asked again without force while its own read runs, that read serves it`,
      c.runsOf(id).length === 3 && !c.queuedReads[name], JSON.stringify(c.queuedReads))
    c.exit(id, 0, "[]", "")
  } else {
    c[starter](true); c.exit(id, 0, "[]", "")
  }
  c[starter](true); c[starter](true); c.dropVaultState()
  c.exit(id, 0, "[]", "")
  eq(`${starter}(): a lock drops the waiting read`, c.runsOf(id).length, 4)
}

// --- an organization's collections: keyed by the organization --------------------------
{
  const c = fixture()
  vm.runInContext(functionBody(source, "setFormOrganization"), c)
  c.setFormOrganization("org-1")
  c.setFormOrganization("org-2")
  eq("a second organization waits for the first one's read", c.runsOf("orgCollectionsProc").length, 1)
  c.exit("orgCollectionsProc", 0, JSON.stringify([{ id: "c1", name: "Of org 1", organizationId: "org-1" }]), "")
  check("the first organization's collections are not offered as the second's",
    c.formCollections.length === 0 && c.formCollectionIds.length === 0 && c.formCollectionsLoading === true,
    JSON.stringify(c.formCollections))
  check("the second organization's read then starts",
    c.runsOf("orgCollectionsProc").length === 2
      && JSON.stringify(c.orgCollectionsProc.command) === JSON.stringify(Model.listOrgCollectionsCommand("org-2")),
    JSON.stringify(c.orgCollectionsProc.command))
  c.exit("orgCollectionsProc", 0, JSON.stringify([{ id: "c2", name: "Of org 2", organizationId: "org-2" }]), "")
  check("and is the one shown", c.formCollections.length === 1 && c.formCollections[0].id === "c2"
    && c.formCollectionsLoading === false, JSON.stringify(c.formCollections))
}

{
  // A, then B, then "personal" while A's read still runs.
  const c = fixture()
  vm.runInContext(functionBody(source, "setFormOrganization"), c)
  c.setFormOrganization("org-1")
  c.setFormOrganization("org-2")
  c.setFormOrganization("personal")
  c.exit("orgCollectionsProc", 0, JSON.stringify([{ id: "c1", name: "Of org 1", organizationId: "org-1" }]), "")
  check("choosing no organization drops the read that was waiting", c.runsOf("orgCollectionsProc").length === 1, JSON.stringify(c.runs))
  check("and the answer still on its way offers and pre-selects nothing in a personal item",
    c.formCollections.length === 0 && c.formCollectionIds.length === 0, JSON.stringify(c.formCollectionIds))
  // An answer for another organization than the form's, however it got here.
  const d = fixture()
  d.formOrgId = "org-2"
  d.loadOrgCollections("org-1")
  d.exit("orgCollectionsProc", 0, JSON.stringify([{ id: "c1", name: "Of org 1", organizationId: "org-1" }]), "")
  check("collections are shown only for the organization the form has", d.formCollections.length === 0 && d.formCollectionIds.length === 0)
}

// --- single-item reads (no helper: `bw get item`) -----------------------------------------
{
  const row = (id, extra) => Object.assign({ id, name: "Item " + id, typeCode: 1, secretsHeld: false }, extra)
  const itemJson = id => JSON.stringify({ object: "item", id, type: 1, name: "Item " + id, login: { username: "u-" + id } })
  const c = fixture(); c.vaultHelperActive = false
  c.openDetail(row("a"), true)
  c.openDetail(row("b"), true)
  eq("a second item opened while the first is being read starts no second command", c.runsOf("getItemProc").length, 1)
  c.exit("getItemProc", 0, itemJson("a"), "")
  check("the first item's answer is not shown as the second's", c.detailItem === null, JSON.stringify(c.detailItem))
  check("the second item's read starts", c.runsOf("getItemProc").length === 2
    && JSON.stringify(c.getItemProc.command) === JSON.stringify(Model.getItemCommand("b", 1)), JSON.stringify(c.getItemProc.command))
  c.exit("getItemProc", 0, itemJson("b"), "")
  check("and is the one shown", c.detailItem && c.detailItem.id === "b", JSON.stringify(c.detailItem))

  // An item that needs no read, opened over one being read.
  const d = fixture(); d.vaultHelperActive = false
  d.openDetail(row("a"), true)
  d.openDetail(row("c", { rawObject: JSON.parse(itemJson("c")) }), true)
  check("premise: the second item is shown from the list", d.detailItem && d.detailItem.id === "c")
  d.exit("getItemProc", 0, itemJson("a"), "")
  check("the read still going for the item open before does not replace it",
    d.detailItem && d.detailItem.id === "c" && d.runsOf("getItemProc").length === 1, JSON.stringify(d.detailItem && d.detailItem.id))

  // Across a lock.
  const e = fixture(); e.vaultHelperActive = false
  e.openDetail(row("a"), true); e.reopenAs("session-b"); e.openDetail(row("b"), true)
  e.exit("getItemProc", 0, itemJson("a"), "")
  check("an item read of the account just left is not shown in the new one",
    e.detailItem === null && e.runsOf("getItemProc").length === 2, JSON.stringify(e.detailItem))
}

// --- a save or delete while a list refresh is in flight -------------------------------
// The save's answer and the refresh's can arrive in either order. The saved
// item goes in once, under the id the save answered with, and a snapshot
// started before the save (or delete) finished is read again, not shown: it
// has replaced the helper's items as well, so only a new read puts both right.
const draft = { type: 1, name: "New login", notes: "", favorite: false, login: { username: "me", password: "pw", uris: [] } }
const provisionalId = Model.pendingItemId(777)
const savedId = "55555555-5555-5555-5555-555555555555"
const oldId = "11111111-1111-1111-1111-111111111111"
const stored = (id, name) => ({ object: "item", id, type: 1, name, login: { username: "me" }, qsbwHeld: { password: true } })
const listOf = (...rows) => JSON.stringify({ sshCapability: "unconfirmed", sshKeys: [], items: rows })
const savedAnswer = listOf(stored(savedId, "New login"))
const ids = c => Array.from(c.items).map(i => i.id).join()
// A vault with one item, a new one being saved (its provisional row listed), and optionally its detail open.
function saving(open) {
  const c = fixture()
  c.loadItems(false); c.exit("listProc", 0, listOf(stored(oldId, "Old")), "")
  c.items = Model.replaceItemById(c.items, provisionalId, Model.optimisticItem(draft, provisionalId))
  c.pendingSave = { id: provisionalId, isCreate: true, name: "New login", previous: null, form: {} }
  c.readEpochs.itemSave = c.vaultEpoch
  if (open) { c.currentScreen = "detail"; c.detailItem = { id: provisionalId, name: "New login", pending: true } }
  return c
}
const finishSave = (c, code, out) => { c.createItemProc = null; c.onSaveItemFinished(code, out, code ? "refused" : "") }
{
  // (a) The refresh, which already lists the saved item, answers first.
  const c = saving(true)
  c.loadItems(false)
  c.exit("listProc", 0, listOf(stored(oldId, "Old"), stored(savedId, "New login")), "")
  check("a snapshot landing while the save runs is not shown: the provisional row and its detail stay",
    ids(c).split(",").sort().join() === [oldId, provisionalId].sort().join() && c.detailItem.id === provisionalId
      && c.listRereadOwed === true && c.runsOf("listProc").length === 2, ids(c))
  finishSave(c, 0, savedAnswer)
  check("the save then puts its item in once, with no provisional row left",
    Array.from(c.items).filter(i => i.id === savedId).length === 1 && c.items.length === 2
      && !Array.from(c.items).some(i => Model.isPendingItemId(i.id)), ids(c))
  check("the open detail moves to the id the save answered with",
    c.detailItem && c.detailItem.id === savedId && c.currentScreen === "detail", JSON.stringify(c.detailItem && c.detailItem.id))
  check("and the list is read again, after the save", c.runsOf("listProc").length === 3 && !c.listRereadOwed
    && c.listReadChanges === c.vaultChanges, JSON.stringify(c.runs.length))
  c.exit("listProc", 0, listOf(stored(oldId, "Old"), stored(savedId, "New login")), "")
  check("whose answer is accepted", c.items.length === 2 && c.runsOf("listProc").length === 3 && !c.listProc.running, ids(c))
}
{
  // (a) again, had that snapshot been shown (as it was): the list holds the
  // saved id and no provisional row when the save answers.
  const c = saving(true)
  c.items = Model.parseItems([stored(oldId, "Old"), stored(savedId, "New login")])
  finishSave(c, 0, savedAnswer)
  check("a saved item a refresh listed first is not inserted a second time",
    c.items.length === 2 && Array.from(c.items).filter(i => i.id === savedId).length === 1, ids(c))
  check("and the detail still moves to it, by the id in the save's answer", c.detailItem && c.detailItem.id === savedId,
    JSON.stringify(c.detailItem && c.detailItem.id))
}
{
  // Several rows are new to the list when the save answers: its id says which is its own.
  const c = saving(true)
  c.items = Model.replaceItemById(c.items, "22222222-2222-2222-2222-222222222222", Model.parseItems([stored("22222222-2222-2222-2222-222222222222", "From a sync")])[0])
  finishSave(c, 0, savedAnswer)
  eq("another new row beside it does not stop the detail following its own save", c.detailItem && c.detailItem.id, savedId)
}
{
  // (b) The save answers first; a snapshot taken before it lands after.
  const c = saving(false)
  c.syncReloadPending = true; c.isSyncing = true
  c.loadItems(true)
  finishSave(c, 0, savedAnswer)
  c.isLoading = true
  eq("premise: the saved row is listed", ids(c).split(",").sort().join(), [oldId, savedId].sort().join())
  c.errorMessage = "kept"; c.listReadError = "kept"
  c.exit("listProc", 0, listOf(stored(oldId, "Old")), "")
  check("a snapshot from before the save does not take the saved row away",
    ids(c).split(",").sort().join() === [oldId, savedId].sort().join(), ids(c))
  check("it settles nothing an accepted list would: the sync, the spinner and the list error wait",
    c.syncReloadPending && c.isSyncing && c.isLoading && c.errorMessage === "kept" && c.flashes.indexOf("Vault synced with Bitwarden") === -1,
    JSON.stringify({ sync: c.syncReloadPending, loading: c.isLoading, error: c.errorMessage }))
  check("the list is read again instead", c.runsOf("listProc").length === 3 && c.listProc.running, String(c.runs.length))
  c.exit("listProc", 0, listOf(stored(oldId, "Old"), stored(savedId, "New login")), "")
  check("and that read is accepted and settles them",
    c.items.length === 2 && !c.syncReloadPending && !c.isSyncing && !c.isLoading && c.errorMessage === ""
      && c.flashes.indexOf("Vault synced with Bitwarden") !== -1 && c.runsOf("listProc").length === 3, ids(c))
}
{
  // A delete: the row is gone at once, and no reload follows a successful one.
  const deleting = () => {
    const c = fixture()
    c.loadItems(false); c.exit("listProc", 0, listOf(stored(oldId, "Old"), stored(savedId, "Doomed")), "")
    c.pendingDelete = { id: savedId, name: "Doomed", previous: Model.findItemById(c.items, savedId) }
    c.readEpochs.itemDelete = c.vaultEpoch
    c.items = Model.replaceItemById(c.items, savedId, null)
    return c
  }
  const c = deleting()
  c.loadItems(false)
  c.onDeleteItemFinished(0, "", "")
  c.exit("listProc", 0, listOf(stored(oldId, "Old"), stored(savedId, "Doomed")), "")
  check("a snapshot from before a delete finished does not bring the deleted row back",
    ids(c) === oldId && c.runsOf("listProc").length === 3, ids(c))
  const d = deleting()
  d.loadItems(false)
  d.exit("listProc", 0, listOf(stored(oldId, "Old"), stored(savedId, "Doomed")), "")
  check("nor one landing while the delete runs", ids(d) === oldId && d.listRereadOwed && d.runsOf("listProc").length === 2, ids(d))
  d.onDeleteItemFinished(0, "", "")
  check("the list is read again once the delete has finished", d.runsOf("listProc").length === 3 && !d.listRereadOwed, String(d.runs.length))
  const r = deleting()
  r.loadItems(false)
  r.exit("listProc", 0, listOf(stored(oldId, "Old"), stored(savedId, "Doomed")), "")
  r.onDeleteItemFinished(1, "", "refused")
  check("a refused delete puts the row back and still reads again",
    ids(r).split(",").sort().join() === [oldId, savedId].sort().join() && r.runsOf("listProc").length === 3, ids(r))
  const k = deleting()
  k.loadItems(false); k.exit("listProc", 0, listOf(stored(oldId, "Old"), stored(savedId, "Doomed")), "")
  k.dropVaultState()
  check("a lock drops the read owed after a delete", k.listRereadOwed === false)
}
{
  // A save still running when its vault is dropped (no helper: a lock does
  // not end it) is not the next vault's business.
  const c = saving(false)
  c.reopenAs("session-b")
  check("premise: the old vault's save is still pending", c.pendingSave !== null && c.vaultReadIsStale("itemSave"))
  c.loadItems(false)
  c.exit("listProc", 0, listOf(stored("id-b", "B")), "")
  check("the next vault's list is shown, not held back for the old vault's save",
    names(c) === "B" && c.listRereadOwed === false, names(c) + " " + c.listRereadOwed)
  finishSave(c, 0, savedAnswer)
  check("and that save's late answer changes nothing in it", names(c) === "B" && c.runsOf("listProc").length === 2 && !c.listRereadOwed, names(c))
}
{
  // A snapshot not shown is read again, and a later read still gets its list in.
  const c = saving(false)
  c.loadItems(false)
  finishSave(c, 0, savedAnswer)
  c.exit("listProc", 0, listOf(stored(oldId, "Old")), "")
  check("a snapshot from before the save is not shown while the list is read again", c.listProc.running)
  c.exit("listProc", 1, "", "Could not safely read vault items.")
  check("that read failing says so", c.errorMessage !== "")
  c.loadItems(false)
  c.exit("listProc", 0, listOf(stored(oldId, "Old"), stored(savedId, "New login")), "")
  check("and the next list is accepted", c.items.length === 2)
  const q = fixture()
  q.loadItems(false); q.vaultChanges += 1; q.loadItems(false)
  q.exit("listProc", 0, vaultOf("old"), "")
  check("an answer replaced by a newer request is not shown", names(q) === "")
}
{
  // Nothing saved or deleted: a refresh is accepted as before, once.
  const c = fixture()
  c.loadItems(false); c.exit("listProc", 0, listOf(stored(oldId, "Old")), "")
  c.loadItems(false); c.exit("listProc", 0, listOf(stored(oldId, "Renamed")), "")
  check("with no save or delete about, a refresh is accepted as it was", names(c) === "Renamed" && c.runsOf("listProc").length === 2, names(c))
}
{
  // The save's answer has no usable id (the unsanitized marker): the list is
  // reloaded, and a detail open on the provisional row goes back to the list.
  const c = saving(true)
  finishSave(c, 0, Model.savedUnsanitizedMarker())
  check("a save answered without an id returns the provisional detail to the list and reloads",
    c.currentScreen === "main" && ids(c) === oldId && c.runsOf("listProc").length === 2, c.currentScreen + " " + ids(c))
  const o = saving(false); o.currentScreen = "detail"; o.detailItem = { id: oldId }
  finishSave(o, 0, Model.savedUnsanitizedMarker())
  eq("a detail open on another item stays", o.currentScreen, "detail")
  // Covered by the in-panel SSH approval: the screen to come back to is the list.
  const s = saving(true); s.currentScreen = "sshApproval"; s.screenBeforeSshApproval = "detail"
  finishSave(s, 0, "not json")
  check("under an SSH approval, the approval stays up and returns to the list",
    s.currentScreen === "sshApproval" && s.screenBeforeSshApproval === "main", s.currentScreen + "/" + s.screenBeforeSshApproval)
}
{
  // The in-panel SSH approval covers the provisional detail as the save answers.
  const c = saving(true); c.currentScreen = "sshApproval"; c.screenBeforeSshApproval = "detail"
  finishSave(c, 0, savedAnswer)
  check("under an SSH approval the save does not take the screen, and the handoff is kept by id only",
    c.currentScreen === "sshApproval" && c.detailItem.id === provisionalId
      && JSON.stringify(c.createdItemHandoff) === JSON.stringify({ from: provisionalId, to: savedId }), JSON.stringify(c.createdItemHandoff))
  c.currentScreen = "detail"; c.resumeCreatedItem()      // dismissSshApproval(), then onCurrentScreenChanged
  check("the detail moves to the saved item when it is back", c.detailItem.id === savedId && c.createdItemHandoff === null
    && c.currentScreen === "detail", JSON.stringify(c.detailItem.id))
  const g = saving(true); g.currentScreen = "sshApproval"; g.screenBeforeSshApproval = "detail"
  finishSave(g, 0, savedAnswer)
  g.items = Model.replaceItemById(g.items, savedId, null)   // a sync removed it meanwhile
  g.currentScreen = "detail"; g.resumeCreatedItem()
  eq("a saved item gone by then leaves the list, not a provisional detail", g.currentScreen, "main")
  const l = saving(true); l.currentScreen = "sshApproval"; l.screenBeforeSshApproval = "detail"
  finishSave(l, 0, savedAnswer); l.dropVaultState()
  eq("a lock drops the handoff", l.createdItemHandoff, null)
  const screenChanged = source.slice(source.indexOf("\n  onCurrentScreenChanged: {"), source.indexOf("function restoreScreenFocus"))
  check("the screen change that brings the detail back runs the handoff",
    /if \(currentScreen === "detail"\) resumeCreatedItem\(\)/.test(screenChanged), screenChanged)
}

// --- the SSH agent's keys from a list that is not shown -----------------------------------
// A list read hands the agent its keys on the way. One whose answer is not
// shown (a newer read was waiting, or it is from before a sync) must not
// publish them, and the keys stay owed until a list that is shown brings them.
{
  const LOAD_ID = "ab".repeat(16)
  const keyed = () => {
    const c = fixture()
    Object.assign(c, { sshAgentGateOpen: true, sshAgentNextLoadId: LOAD_ID, ended: [], lifecycle: [], primed: 0,
      sshPendingCount: 0, endSshAgentLoad: ok => { c.ended.push(ok); c.sshAgentLoadActive = false },
      applySshAgentLifecycle: e => c.lifecycle.push(e), primeSshAgentLoadId: () => { c.primed++ } })
    vm.runInContext(functionBody(source, "maybeStartupLoad"), c)
    return c
  }
  const c = keyed()
  c.loadItems(false)
  check("premise: the read carries the agent's keys and marks them loaded for this vault",
    c.listAgentBranchActive && c.sshAgentLoadActive && c.sshAgentLoadedForVaultEpoch === c.vaultEpoch)
  c.vaultChanges += 1; c.loadItems(false)      // a save finished: a newer read waits
  c.exit("listProc", 0, vaultOf("old"), "")
  eq("a superseded list's key batch is ended as failed, so the agent discards it", c.ended.join(), "false")
  check("the waiting read starts without keys, and the keys are owed again",
    c.runsOf("listProc").length === 2 && !c.listAgentBranchActive && c.sshAgentLoadedForVaultEpoch === -1)
  c.sshAgentNextLoadId = LOAD_ID                // the next nonce is in by the time it lands
  c.exit("listProc", 0, vaultOf("new"), "")
  check("the list that is shown is followed by the key load that was owed",
    names(c) === "new" && c.lifecycle.join() === "startup" && c.sshAgentLoadedForVaultEpoch === c.vaultEpoch, c.lifecycle.join())

  const o = keyed()
  o.loadItems(false)
  o.vaultChanges += 1                           // a manual sync finished meanwhile
  o.exit("listProc", 0, vaultOf("old"), "")
  check("a snapshot from before a sync does not publish its keys either",
    o.ended.join() === "false" && o.sshAgentLoadedForVaultEpoch === -1 && o.runsOf("listProc").length === 2, o.ended.join())

  const f = keyed()
  f.loadItems(false)
  f.vaultChanges += 1; f.loadItems(false)
  f.exit("listProc", 1, "", "failed")
  check("a superseded read that failed leaves the keys owed to the read that replaces it",
    f.ended.join() === "false" && f.sshAgentLoadedForVaultEpoch === -1 && f.runsOf("listProc").length === 2)

  const k = keyed()
  k.loadItems(false)
  k.exit("listProc", 0, vaultOf("only"), "")
  check("a list that is shown publishes its keys, once",
    k.ended.join() === "true" && k.sshAgentLoadedForVaultEpoch === k.vaultEpoch && k.lifecycle.length === 0, k.ended.join())

  const p = keyed()
  p.sshPendingCount = 1
  p.maybeStartupLoad()
  check("a key load that is owed waits for a pending SSH approval", p.lifecycle.length === 0 && p.sshAgentLoadedForVaultEpoch === -1)
  p.sshPendingCount = 0
  p.maybeStartupLoad()
  eq("and runs once it is answered", p.lifecycle.join(), "startup")
  check("the answer is what asks again", /onSshPendingCountChanged: if \(sshPendingCount === 0\) maybeStartupLoad\(\)/.test(source))
}

// --- an automatic sync's reload and a list from before it ---------------------------------
// The reload an automatic sync owes waits for an idle vault (maybeAutoSync():
// not over an edit, not over an SSH approval, which a key load would fail).
// A list from before the sync is not shown, and is not read again past that gate.
{
  const synced = () => {
    const c = fixture()
    c.idleChecks = 0
    c.maybeAutoSync = () => { c.idleChecks++ }
    c.loadItems(false)
    c.vaultChanges += 1; c.autoSyncReloadPending = true      // onSyncFinished(0), in the background
    return c
  }
  const c = synced()
  c.exit("listProc", 0, vaultOf("old"), "")
  check("a list from before an automatic sync is not shown, and its re-read is left to the idle gate",
    names(c) === "" && c.runsOf("listProc").length === 1 && c.idleChecks === 1 && c.autoSyncReloadPending === true,
    c.runsOf("listProc").length + " " + c.idleChecks)
  const u = synced()
  u.isLoading = true                             // the user asked for this read, and is watching a spinner
  u.exit("listProc", 0, vaultOf("old"), "")
  check("a read the user is waiting for is read again at once", u.runsOf("listProc").length === 2 && u.idleChecks === 0)
}

{
  // A create the vault refused: its provisional row is gone, and so is a detail open on it.
  const c = saving(true)
  finishSave(c, 1, "")
  check("a refused create leaves the list, not a detail of a row that is gone",
    c.currentScreen === "main" && !Array.from(c.items).some(i => Model.isPendingItemId(i.id)), c.currentScreen)
  check("and keeps the draft for reopening", c.failedSave !== null && c.failedSave.name === "New login")
  const g = saving(true); g.currentScreen = "sshApproval"; g.screenBeforeSshApproval = "detail"
  finishSave(g, 1, "")
  check("under an SSH approval it is the list the approval returns to",
    g.currentScreen === "sshApproval" && g.screenBeforeSshApproval === "main", g.screenBeforeSshApproval)
  const e = saving(false); e.currentScreen = "detail"; e.detailItem = { id: oldId, name: "Old" }
  finishSave(e, 1, "")
  eq("a detail open on another item stays", e.currentScreen, "detail")
}

check("the waiting reads are per-vault state a lock drops", /queuedReads = \(\{\}\)/.test(functionBody(source, "dropVaultState")))
for (const id of ["listOrgsProc", "listFoldersProc", "orgCollectionsProc", "listSendsProc", "getItemProc"]) {
  // The scrub is recognised by the process's command, which a waiting read's
  // start replaces: asked first.
  const body = exitHandler(id)
  check(`${id}: the scrub is recognised before a waiting read starts`,
    /var scrub = root\.finishScrubRun\(\w+\)\s*if \(root\.supersededVaultRead\("\w+"\) \|\| scrub\) return/.test(body), body)
}

done()
