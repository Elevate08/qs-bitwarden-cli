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
  "vaultProcBusy", "startVaultRead", "supersededVaultRead", "finishScrubRun",
  "loadItems", "abandonSyncReload", "startVaultListRead", "vaultListEnv", "onListFinished", "onListProcessExited",
  "loadOrganizations", "onListOrgsFinished", "loadFolders", "onListFoldersFinished",
  "loadOrgCollections", "onOrgCollectionsLoaded", "loadSends", "onSendsLoaded",
  "openDetail", "onDetailFinished", "itemNeedsReprompt", "dropVaultState"]

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
    closeFilterGroup() {}, clearRepromptGrant() {}, learnFromPick() {}, fetchTotp() {}
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
  const c = fixture()
  c.loadItems(false); c.loadItems(false); c.loadItems(false)
  eq("a refresh asked for during a refresh runs once, after it", c.runsOf("listProc").length, 1)
  c.exit("listProc", 0, vaultOf("old"), "")
  check("the earlier snapshot is not shown; the read asked for since replaces it",
    names(c) === "" && c.runsOf("listProc").length === 2, names(c))
  c.exit("listProc", 0, vaultOf("new"), "")
  check("and nothing is left waiting", names(c) === "new" && c.runsOf("listProc").length === 2 && !c.listProc.running, names(c))
}
{
  const c = fixture()
  c.loadItems(false); c.loadItems(false)
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
  c[starter](true); c[starter](true); c.dropVaultState()
  c.exit(id, 0, "[]", "")
  eq(`${starter}(): a lock drops the waiting read`, c.runsOf(id).length, 3)
}

// --- an organization's collections: keyed by the organization --------------------------
{
  const c = fixture()
  c.loadOrgCollections("org-1")
  c.loadOrgCollections("org-2")
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

check("the waiting reads are per-vault state a lock drops", /queuedReads = \(\{\}\)/.test(functionBody(source, "dropVaultState")))
for (const id of ["listOrgsProc", "listFoldersProc", "orgCollectionsProc", "listSendsProc", "getItemProc"]) {
  // The scrub is recognised by the process's command, which a waiting read's
  // start replaces: asked first.
  const body = exitHandler(id)
  check(`${id}: the scrub is recognised before a waiting read starts`,
    /var scrub = root\.finishScrubRun\(\w+\)\s*if \(root\.supersededVaultRead\("\w+"\) \|\| scrub\) return/.test(body), body)
}

done()
