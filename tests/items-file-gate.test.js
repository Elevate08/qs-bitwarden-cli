#!/usr/bin/env node
// Opening the panel re-reads the item list once it is a minute old. That read
// is skipped while bw's data file is exactly as it was before the read the
// list came from -- and only then: a file that cannot be stat'ed, a new
// session, a sync, a failed read or an SSH agent still owed its keys all read
// as before. The file's contents are never read, and what is remembered of
// it goes with the vault on lock.
//
//   node tests/items-file-gate.test.js

const fs = require("fs")
const os = require("os")
const path = require("path")
const vm = require("vm")
const { spawnSync } = require("child_process")
const { createSuite, functionBody, loadModule, read } = require("./harness")

const { check, eq, done } = createSuite("items-file-gate")
const Model = loadModule()
const source = read("Service.qml")
const body = name => functionBody(source, name)

// --- which file ------------------------------------------------------------------

const slot = "0123456789abcdef"
eq("the default account's file is where bw keeps it",
  Model.bwDataFilePath("default", "", "", "", "/home/u"), "/home/u/.config/Bitwarden CLI/data.json")
eq("...under XDG_CONFIG_HOME when that is set",
  Model.bwDataFilePath("default", "", "", "/home/u/cfg/", "/home/u"), "/home/u/cfg/Bitwarden CLI/data.json")
eq("...or in the BITWARDENCLI_APPDATA_DIR the shell itself runs with, which bw then inherits",
  Model.bwDataFilePath("default", "", "/srv/bw/", "/home/u/cfg", "/home/u"), "/srv/bw/data.json")
eq("an added account's file is in its own directory, whatever the shell's environment says",
  Model.bwDataFilePath(slot, "/home/u/.local/share/qs-bitwarden-cli/accounts/" + slot, "/srv/bw", "/home/u/cfg", "/home/u"),
  "/home/u/.local/share/qs-bitwarden-cli/accounts/" + slot + "/data.json")
check("a path that is not certain is no path: bw resolves these against its own working directory",
  Model.bwDataFilePath(slot, "", "/srv/bw", "/home/u/cfg", "/home/u") === ""
    && Model.bwDataFilePath("default", "", "relative/dir", "", "/home/u") === ""
    && Model.bwDataFilePath("default", "", "", "relative", "/home/u") === ""
    && Model.bwDataFilePath("default", "", "", "", "") === ""
    && Model.bwDataFilePath("default", "", "", "", "home") === "")
check("a path bw would rewrite before using it is no path either: bw normalizes as text, stat follows links",
  Model.bwDataFilePath("default", "", "/srv/link/../bw", "", "/home/u") === ""
    && Model.bwDataFilePath("default", "", "/srv/./bw", "", "/home/u") === ""
    && Model.bwDataFilePath("default", "", "/srv//bw", "", "/home/u") === ""
    && Model.bwDataFilePath("default", "", "", "/home/u/link/..", "/home/u") === ""
    && Model.bwDataFilePath("default", "", "", "", "/home/u/../v") === ""
    && Model.bwDataFilePath("default", "", "/srv/bw\n", "", "/home/u") === ""
    && Model.bwDataFilePath(slot, "/home/u/x/../accounts/" + slot, "", "", "/home/u") === ""
    && Model.bwDataFilePath("default", "", "/srv/..bw/a.b", "", "") === "/srv/..bw/a.b/data.json")
check("the panel resolves it for the active account, from the same directory it hands bw",
  /bwDataFile: Model\.bwDataFilePath\(activeSlot, accountAppDataDir,\s*Quickshell\.env\(Model\.appDataEnvVar\(\)\) \|\| "", Quickshell\.env\("XDG_CONFIG_HOME"\) \|\| "", Quickshell\.env\("HOME"\) \|\| ""\)/.test(source))

// --- the stat ----------------------------------------------------------------------

const tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "qsbw-items-file-")))
const file = path.join(tmp, "Bitwarden CLI", "data.json")
fs.mkdirSync(path.dirname(file))
fs.writeFileSync(file, "{\"a\":\"0123456789\"}")
const statOf = (f, env) => {
  const cmd = Model.bwDataStatCommand(f)
  // As the panel runs it: nothing of the caller's environment but PATH.
  const r = spawnSync(cmd[0], cmd.slice(1), { encoding: "utf8", env: env || Model.plainProbeEnv(process.env.PATH) })
  return { rc: r.status, stat: Model.bwDataStat(r.stdout), out: r.stdout }
}
const first = statOf(file)
check("the stat is device, inode, size, and both times to the nanosecond",
  first.rc === 0 && /^\d+:\d+:18:\d+\.\d{9}:\d+\.\d{9}$/.test(first.stat), JSON.stringify(first))
eq("an untouched file stats the same", statOf(file).stat, first.stat)
fs.writeFileSync(file, "{\"a\":\"9876543210\"}")
const rewritten = statOf(file)
check("a rewrite of the same length, as bw makes for an edit that keeps a value's length, is a change",
  rewritten.stat !== "" && rewritten.stat !== first.stat, rewritten.stat)
fs.utimesSync(file, new Date(1000), new Date(1000))
const backdated = statOf(file)
fs.writeFileSync(file, "{\"a\":\"1111111111\"}")
fs.utimesSync(file, new Date(1000), new Date(1000))
check("...even with its modification time put back", statOf(file).stat !== backdated.stat && backdated.stat !== "")
const before = statOf(file).stat
fs.writeFileSync(file + ".new", "{\"a\":\"1111111111\"}")
fs.utimesSync(file + ".new", new Date(1000), new Date(1000))
fs.renameSync(file + ".new", file)
check("a file put in its place is a change", statOf(file).stat !== before)
fs.chmodSync(file, 0)
const sealed = statOf(file)
check("a file that cannot be opened still stats: its contents are not read",
  sealed.rc === 0 && sealed.stat !== "" && !/\bcat\b|\bhead\b|\bjq\b|\bnode -e\b|<\s*"\$1"/.test(Model.bwDataStatCommand(file)[2]),
  JSON.stringify(sealed))
check("a missing file, a relative path and no path give no stat",
  statOf(path.join(tmp, "absent", "data.json")).stat === "" && statOf(path.join(tmp, "absent", "data.json")).rc !== 0
    && statOf("data.json").rc !== 0 && statOf("").rc !== 0)
check("the path is an argument, not part of the script",
  Model.bwDataStatCommand("/a b/$(x)")[4] === "/a b/$(x)" && !/\/a b/.test(Model.bwDataStatCommand("/a b/$(x)")[2]))
{
  // bw prefers a `bw-data` directory beside its executable to every path above.
  const bin = path.join(tmp, "bin")
  fs.mkdirSync(bin)
  for (const name of ["node", "bw"]) fs.writeFileSync(path.join(bin, name), "#!/bin/sh\n", { mode: 0o755 })
  const env = Model.plainProbeEnv(bin + ":" + process.env.PATH)
  const plain = statOf(file, env)
  fs.mkdirSync(path.join(bin, "bw-data"))
  const portable = statOf(file, env)
  check("with a bw-data directory beside node or bw the file is not bw's, and there is no stat",
    plain.rc === 0 && plain.stat !== "" && portable.rc !== 0 && portable.stat === "", JSON.stringify([plain, portable]))
}
{
  // A symlink on the way to the file: bw may be reading another file by the
  // time it runs, so there is nothing to remember a read by.
  const real = path.join(tmp, "real-dir")
  fs.mkdirSync(real)
  fs.writeFileSync(path.join(real, "data.json"), "{}")
  fs.symlinkSync(real, path.join(tmp, "linked-dir"))
  fs.symlinkSync(path.join(real, "data.json"), path.join(tmp, "linked.json"))
  check("a file reached through a symlinked directory, or that is itself a symlink, gives no stat",
    statOf(path.join(real, "data.json")).stat !== ""
      && statOf(path.join(tmp, "linked-dir", "data.json")).rc !== 0 && statOf(path.join(tmp, "linked-dir", "data.json")).stat === ""
      && statOf(path.join(tmp, "linked.json")).rc !== 0)
  check("...nor does a path that is not written the canonical way",
    statOf(real + "/./data.json").rc !== 0 && statOf(real + "//data.json").rc !== 0
      && statOf(path.join(tmp, "linked-dir") + "/../real-dir/data.json").rc !== 0)
  check("the stat runs with PATH and a fixed locale, whatever the shell's own environment holds",
    /id: itemsFileStatProc\s+clearEnvironment: true\s+environment: Model\.plainProbeEnv\(Quickshell\.env\("PATH"\) \|\| ""\)/.test(source)
      && Object.keys(Model.plainProbeEnv("/usr/bin")).join() === "PATH,LC_ALL" && Model.plainProbeEnv("/usr/bin").LC_ALL === "C")
}
check("only the one line the stat prints is a stat",
  Model.bwDataStat("") === "" && Model.bwDataStat("1:2:3:4:5") === "" && Model.bwDataStat("1:2:3:4.000000000:5.000000000\n") !== ""
    && Model.bwDataStat("1:2:3:4.000000000:5.000000000\n6:7:8:9.000000000:1.000000000") === ""
    && Model.bwDataStat("x:2:3:4.000000000:5.000000000") === "" && Model.bwDataStat(undefined) === "")
check("a stamp is the stat for one file in one vault epoch, and nothing without a stat",
  Model.bwDataStamp(3, "/f", "1:2:3:4.000000000:5.000000000") === "3|/f|1:2:3:4.000000000:5.000000000"
    && Model.bwDataStamp(3, "/f", "") === "" && Model.bwDataStamp(3, "/f", "junk") === "" && Model.bwDataStamp(3, "", "1:2:3:4.000000000:5.000000000") === "")
fs.rmSync(tmp, { recursive: true, force: true })

// --- the gate ----------------------------------------------------------------------

const STAT_A = "1:2:300:10.000000001:10.000000001"
const STAT_B = "1:2:300:20.000000002:20.000000002"
const listJson = JSON.stringify({ items: [{ object: "item", id: "a", type: 1, name: "A", login: {} }], sshKeys: [] })
const functions = ["ensureItemsFresh", "probeItemsFile", "onItemsFileProbed", "onItemsFileStatOverdue", "forgetItemsFileStamp",
  "sshAgentOwedKeys", "beginInitialVaultLoad", "loadPendingMetadata", "loadItems", "startVaultListRead",
  "onListFinished", "onSyncFinished", "dropVaultState", "abandonSyncReload", "beginVaultRead",
  "vaultReadIsStale", "beginEpochOperation", "epochOperationIsStale"]

function fixture() {
  const c = {
    now: 1000000, session: "test-session", status: "unlocked", vaultEpoch: 4, readEpochs: {},
    bwDataFile: "/home/u/.config/Bitwarden CLI/data.json", itemsFreshMs: 60000,
    items: [], itemsLoadedAt: 0, itemsFileStamp: "", itemsFileStampNext: "", listReadStamp: "",
    itemsFileProbe: null, itemsFileStatLine: "", itemsFileStampGen: 0, autoSyncMinutes: 15,
    deadline: false, listReadError: "", errorMessage: "",
    activeWindowData: null, isLoading: false, isSyncing: false, syncReloadPending: false,
    backgroundSync: false, autoSyncReloadPending: false, autoSyncError: "x",
    metadataLoadPending: false, metadataForceRefresh: false, statusRefreshAfterItems: false,
    listReadEarly: false, listReadMode: "", listAgentBranchActive: false, sshCapability: "",
    sshAgentGateOpen: false, sshAgentNextLoadId: "", sshAgentLoadedForVaultEpoch: -1, sshAgentLoadFailStreak: 0,
    dependencies: Model.parseDependencies("bw=1\njq=1\nomarchy=1", null, {}),
    reads: 0, stats: [], metadata: [], filters: 0, Model,
    rebuildFilter: () => { c.filters += 1 }, handleActiveWindowDetected() {},
    loadOrganizations: force => c.metadata.push(["orgs", force]),
    loadFolders: force => c.metadata.push(["folders", force]),
    vaultListEnv: () => ({}), refreshDerivedFromItems() {}, maybeStartupLoad() {}, flashNotification() {},
    maybeAutoSync() {}, deferredMetadataTimer: { restart() {} },
    itemsFileStatProc: { running: false, command: [] },
    itemsFileStatDeadline: { restart() { c.deadline = true }, stop() { c.deadline = false } },
    listProc: { command: [], environment: {} }
  }
  // Like a VaultProcess: starting one that runs is not a second run.
  let listRunning = false
  Object.defineProperty(c.listProc, "running", {
    get: () => listRunning,
    set: v => { if (v && !listRunning) c.reads += 1; listRunning = v }
  })
  let statRunning = false
  Object.defineProperty(c.itemsFileStatProc, "running", {
    get: () => statRunning,
    set: v => { if (v && !statRunning) c.stats.push(c.itemsFileStatProc.command[4]); statRunning = v }
  })
  for (const name of ["cancelEnvelopeUnlockJobs", "cancelPinentry", "resetPinentryChoice",
    "cancelFingerprintUnlock", "cancelFidoUnlock", "cancelAttachmentDownloads",
    "forgetVault", "resetItemForm", "dropVaultSecrets"]) c[name] = () => {}
  c.Date = { now: () => c.now }
  c.root = c
  vm.createContext(c)
  vm.runInContext(functions.map(n => functionBody(source, n)).join("\n"), c)
  // The list read ends, as onListProcessExited() ends a good one.
  c.listDone = () => { c.listProc.running = false; c.onListFinished(listJson) }
  // The stat answers with `stat`, or fails.
  c.statDone = stat => {
    c.itemsFileStatProc.running = false
    if (stat) c.itemsFileStatLine = stat
    c.onItemsFileProbed(stat ? 0 : 1)
  }
  c.open = () => { c.now += 61000; c.ensureItemsFresh() }
  return c
}

// The first load, as after an unlock: no stat was taken before it.
function loaded() {
  const c = fixture()
  c.beginInitialVaultLoad(true, false)
  c.listDone()
  c.metadata = []
  return c
}

{
  const c = loaded()
  check("the read after unlock is one read, with no stat and nothing remembered of the file",
    c.reads === 1 && c.stats.length === 0 && c.itemsFileStamp === "" && c.items.length === 1)
  c.now += 30000
  c.ensureItemsFresh()
  check("a fresh list is shown as it is: no stat, no read", c.reads === 1 && c.stats.length === 0 && c.filters === 1)

  c.now += 31000
  c.ensureItemsFresh()
  check("a stale list is shown at once, and a stat of the account's file goes first",
    c.filters === 2 && c.reads === 1 && c.stats.length === 1 && c.stats[0] === c.bwDataFile)
  c.statDone(STAT_A)
  check("nothing is known of the file as that list was read, so it is read again", c.reads === 2)
  c.listDone()
  eq("...and that read is remembered by the stat taken before it started",
    c.itemsFileStamp, Model.bwDataStamp(4, c.bwDataFile, STAT_A))

  const loadedAt = c.itemsLoadedAt
  c.metadata = []
  c.open()
  c.statDone(STAT_A)
  check("the file unchanged: the list stands and bw is not run", c.reads === 2 && c.stats.length === 2 && !c.isLoading)
  check("...the list's age still counts from the read", c.itemsLoadedAt === loadedAt)
  check("...and organizations and folders are asked for on their own clock, unforced, as a re-read asks",
    JSON.stringify(c.metadata) === JSON.stringify([["orgs", false], ["folders", false]]) && !c.metadataLoadPending,
    JSON.stringify(c.metadata))
  c.open()
  c.statDone(STAT_A)
  check("every later open stats again", c.reads === 2 && c.stats.length === 3)

  c.open()
  c.statDone(STAT_B)
  check("the file changed: the list is read again, behind the one shown", c.reads === 3 && !c.isLoading)
  c.listDone()
  eq("...and remembered by the new stat", c.itemsFileStamp, Model.bwDataStamp(4, c.bwDataFile, STAT_B))
}
{
  const c = loaded()
  c.open(); c.statDone(STAT_A); c.listDone()
  c.open()
  c.statDone("")
  check("a stat that fails reads the list, as before", c.reads === 3)
  c.listDone()
  check("...and that read is remembered by nothing, so the next open reads too",
    c.itemsFileStamp === "" && (c.open(), c.statDone(STAT_A), c.reads === 4))
}
{
  const c = loaded()
  c.open(); c.statDone(STAT_A); c.listDone()
  c.open()
  c.itemsFileStatProc.running = false
  c.itemsFileStatLine = "garbage"
  c.onItemsFileProbed(0)
  check("an answer that is not a stat reads the list", c.reads === 3)
}
{
  const c = loaded()
  c.bwDataFile = ""
  c.open()
  check("with no certain path there is no stat and the list is read at once, as before",
    c.stats.length === 0 && c.reads === 2)
}
{
  const c = loaded()
  c.open(); c.statDone(STAT_A); c.listDone()
  c.open()
  check("a stat that has not answered by the next open is given up on, and the list is read",
    c.stats.length === 2 && (c.open(), c.reads === 3 && c.itemsFileProbe === null))
  c.statDone(STAT_A)
  check("...its late answer starts nothing", c.reads === 3)
}
{
  const c = loaded()
  c.open(); c.statDone(STAT_A); c.listDone()
  c.listReadError = "Could not safely read the vault"
  c.open()
  check("after a failed read the list is read again, whatever the file says", c.stats.length === 1 && c.reads === 3)
  const d = loaded()
  d.open(); d.statDone(STAT_A); d.listDone()
  d.open()
  d.listReadError = "Could not safely read the vault"
  d.statDone(STAT_A)
  check("...also when the read failed while the stat ran", d.reads === 3)
}
{
  const c = loaded()
  c.open(); c.statDone(STAT_A); c.listDone()
  c.sshAgentGateOpen = true
  c.sshAgentLoadedForVaultEpoch = 4
  c.open(); c.statDone(STAT_A)
  check("an SSH agent that has its keys does not force a read", c.reads === 2)
  c.sshAgentLoadFailStreak = 2
  c.open()
  check("an SSH agent whose key load failed gets the read that hands it its keys", c.reads === 3 && c.stats.length === 2)
  c.listDone()
  c.sshAgentLoadFailStreak = 0
  c.sshAgentLoadedForVaultEpoch = -1
  c.open()
  check("...and so does one with no load yet for this vault", c.reads === 4)
}
{
  // A read already running when the stat answers began before the stat.
  const c = loaded()
  c.beginInitialVaultLoad(false, true)
  c.open()
  c.statDone(STAT_A)
  c.listDone()
  check("a read that started before the stat is not remembered by it", c.itemsFileStamp === "" && c.reads === 2)
}
{
  const c = loaded()
  c.open(); c.statDone(STAT_A); c.listDone()
  c.syncReloadPending = true
  c.backgroundSync = true
  c.isSyncing = true
  c.readEpochs.sync = 4
  c.onSyncFinished(0)
  check("a sync forgets the file: its reload, and an open before it, read as before",
    c.itemsFileStamp === "" && c.itemsFileStampNext === "" && c.itemsLoadedAt === 0
      && (c.ensureItemsFresh(), c.stats.length === 2 && c.statDone(STAT_A), c.reads === 3))
}
{
  const c = loaded()
  c.open(); c.statDone(STAT_A); c.listDone()
  c.open()
  c.dropVaultState()
  check("a lock, logout or account switch forgets the stamp, the stat kept for the next read and the stat in flight",
    c.itemsFileStamp === "" && c.itemsFileStampNext === "" && c.listReadStamp === ""
      && c.itemsFileProbe === null && c.itemsFileStatLine === "")
  c.session = "next-session"
  c.status = "unlocked"
  c.statDone(STAT_A)
  check("...and the old vault's stat, answering after it, starts nothing and is kept by nothing",
    c.reads === 2 && c.itemsFileStampNext === "" && c.itemsFileStatLine === "")
}
{
  const c = loaded()
  c.open(); c.statDone(STAT_A); c.listDone()
  c.vaultEpoch += 1
  c.readEpochs.items = c.vaultEpoch
  c.open(); c.statDone(STAT_A)
  check("a new session is a new epoch: the same file reads again", c.reads === 3)
  const d = loaded()
  d.open(); d.statDone(STAT_A); d.listDone()
  d.open()
  d.bwDataFile = "/home/u/.local/share/qs-bitwarden-cli/accounts/" + slot + "/data.json"
  d.statDone(STAT_A)
  check("a stat of another account's file decides nothing", d.reads === 2 && d.itemsFileStampNext === Model.bwDataStamp(4, "/home/u/.config/Bitwarden CLI/data.json", STAT_A))
}

// --- the list changed here, not in the file ---------------------------------------

// A save or delete changes the list in memory; one that bw refuses puts the
// row back without the file ever changing. The stamp says what a read
// returned, so it cannot outlive any of them.
{
  const lines = source.split("\n")
  const sites = []
  lines.forEach((l, i) => { if (/^\s*(if \([^)]*\) )?items = /.test(l)) sites.push(i) })
  const forgets = i => /forgetItemsFileStamp\(\)/.test(lines.slice(i + 1, i + 3).join("\n"))
  const inFunction = (i, name) => { const b = body(name); return b !== "" && b.indexOf(lines[i].trim()) !== -1 }
  const other = sites.filter(i => !inFunction(i, "onListFinished") && !inFunction(i, "dropVaultState"))
  check("every place the list is changed outside a list read forgets the stamp",
    sites.length === 8 && other.length === 6 && other.every(forgets),
    other.filter(i => !forgets(i)).map(i => (i + 1) + ": " + lines[i].trim()).join(" | ") + " of " + sites.length)
  check("...the optimistic row, a refused save, the saved item, a delete and a refused delete among them",
    /items = Model\.replaceItemById\(items, rowId, optimistic\)\s+itemsLoadedAt = Date\.now\(\)\s+forgetItemsFileStamp\(\)/.test(source)
      && /items = Model\.replaceItemById\(items, save\.id, save\.previous\)\s+itemsLoadedAt = Date\.now\(\)\s+forgetItemsFileStamp\(\)/.test(source)
      && /items = Model\.replaceItemById\(items, save\.id, null\)\s+forgetItemsFileStamp\(\)\s+loadItems\(\)/.test(source)
      && /items = spliced\s+itemsLoadedAt = Date\.now\(\)\s+forgetItemsFileStamp\(\)/.test(source)
      && /items = Model\.replaceItemById\(items, id, null\)\s+itemsLoadedAt = Date\.now\(\)\s+forgetItemsFileStamp\(\)/.test(source)
      && /items = Model\.replaceItemById\(items, removal\.id, removal\.previous\)\s+itemsLoadedAt = Date\.now\(\)\s+forgetItemsFileStamp\(\)/.test(source))

  const c = loaded()
  c.open(); c.statDone(STAT_A); c.listDone()
  // As a refused save does: the previous row put back, bw having written nothing.
  c.items = Model.replaceItemById(c.items, "a", c.items[0])
  c.itemsLoadedAt = c.now
  c.forgetItemsFileStamp()
  c.open(); c.statDone(STAT_A)
  check("after a refused save the next stale open reads, though the file is as it was", c.reads === 3)
  c.listDone()
  c.open(); c.statDone(STAT_A)
  check("...and the opens after that read are skipped again", c.reads === 3 && c.itemsFileStamp !== "")

  const d = loaded()
  d.open(); d.statDone(STAT_A)
  d.forgetItemsFileStamp()
  d.listDone()
  check("a read in flight while the list is changed here is remembered by nothing", d.itemsFileStamp === "")
}

// --- a stat from before does not outlive what made it stale -------------------------

{
  const c = loaded()
  c.open(); c.statDone(STAT_A); c.listDone()
  c.open()                      // the stat is in flight
  c.forgetItemsFileStamp()      // a save begins, or a sync ends
  c.statDone(STAT_A)
  check("a stat begun before the list was changed still gets that open its read",
    c.reads === 3)
  check("...but is not what that read, or any later one, is remembered by",
    c.listReadStamp === "" && c.itemsFileStampNext === "" && (c.listDone(), c.itemsFileStamp === ""))
  c.open(); c.statDone(STAT_A); c.listDone()
  check("the stat of the next open is", c.itemsFileStamp === Model.bwDataStamp(4, c.bwDataFile, STAT_A) && c.reads === 4)
}
{
  const c = loaded()
  c.open(); c.statDone(STAT_A); c.listDone()
  c.isSyncing = true
  c.readEpochs.sync = 4
  const loadedAt = c.itemsLoadedAt
  c.onSyncFinished(1)
  check("a sync that failed forgets the file too, without making the list look freshly read",
    c.itemsFileStamp === "" && c.itemsFileStampNext === "" && c.itemsLoadedAt === loadedAt && !c.isSyncing)
  c.open(); c.statDone(STAT_A)
  check("...so the next stale open reads, though the stat is what it was", c.reads === 3)
}

// --- a match is not believed for ever ----------------------------------------------

check("the cap is the automatic sync's interval, or 15 minutes when that is off",
  Model.itemsFileSkipMaxMinutes() === 15 && Model.itemsFileSkipMaxMs(5) === 5 * 60000 && Model.itemsFileSkipMaxMs(60) === 60 * 60000
    && Model.itemsFileSkipMaxMs(0) === 15 * 60000 && Model.itemsFileSkipMaxMs(-1) === 15 * 60000
    && Model.itemsFileSkipMaxMs(undefined) === 15 * 60000 && Model.itemsFileSkipMaxMs(Infinity) === 15 * 60000
    && Model.itemsFileSkipMaxMs("x") === 15 * 60000)
for (const [minutes, cap] of [[15, 15], [5, 5], [0, 15]]) {
  const c = loaded()
  c.autoSyncMinutes = minutes
  c.open(); c.statDone(STAT_A); c.listDone()
  const readAt = c.now
  c.now = readAt + cap * 60000 - 1000
  c.ensureItemsFresh(); c.statDone(STAT_A)
  check(`auto-sync ${minutes}: just under ${cap} minutes after the read, a matching stat still skips`, c.reads === 2)
  c.now = readAt + cap * 60000
  c.ensureItemsFresh(); c.statDone(STAT_A)
  check(`auto-sync ${minutes}: at ${cap} minutes the list is read again, whatever the stat says`, c.reads === 3)
  c.listDone()
  c.open(); c.statDone(STAT_A)
  check(`auto-sync ${minutes}: ...and that read starts the clock again`, c.reads === 3 && c.itemsLoadedAt === readAt + cap * 60000)
}

// --- a stat that does not answer ----------------------------------------------------

{
  check("the deadline is a second",
    Model.itemsFileStatDeadlineMs() === 1000
      && /id: itemsFileStatDeadline\s+interval: Model\.itemsFileStatDeadlineMs\(\)\s+onTriggered: root\.onItemsFileStatOverdue\(\)/.test(source))
  const c = loaded()
  c.open(); c.statDone(STAT_A); c.listDone()
  c.open()
  check("a stat starts its deadline", c.deadline === true && c.reads === 2)
  c.onItemsFileStatOverdue()
  check("past the deadline the same open gets its read, and the stat is stopped",
    c.reads === 3 && c.itemsFileStatProc.running === false && c.itemsFileProbe === null && !c.isLoading)
  c.itemsFileStatLine = STAT_A
  c.onItemsFileProbed(0)
  check("...its answer, should it still come, starts nothing more and is kept by nothing",
    c.reads === 3 && c.itemsFileStatLine === "")
  c.listDone()
  const d = loaded()
  d.open(); d.statDone(STAT_A); d.listDone()
  d.open(); d.statDone(STAT_A)
  check("a stat that answers in time stops the deadline", d.deadline === false)
  d.open()
  d.dropVaultState()
  d.onItemsFileStatOverdue()
  check("a deadline that passes after a lock reads nothing", d.reads === 2)
  const e = loaded()
  e.open(); e.statDone(STAT_A); e.listDone()
  e.open()
  e.vaultEpoch += 1
  e.onItemsFileStatOverdue()
  check("...nor one for another vault epoch", e.reads === 2)
}

// --- only the open is gated --------------------------------------------------------

const callers = source.split("\n").filter(l => /\bprobeItemsFile\(\)/.test(l) && !/function probeItemsFile/.test(l))
check("only ensureItemsFresh() asks, and only for a list it is already showing",
  callers.length === 1 && /if \(!stale\) return\s+(\/\/[^\n]*\n\s*)*if \(probeItemsFile\(\)\) return\s+\}\s+beginInitialVaultLoad\(!haveItems, false\)/.test(body("ensureItemsFresh")),
  body("ensureItemsFresh"))
check("a manual sync, a save's reload and an unlock still read without asking the file",
  !/probeItemsFile|itemsFileStamp ===/.test(body("syncVault") + body("loadItems") + body("beginInitialVaultLoad") + body("maybeAutoSync")))
check("a session handed over from the terminal forgets the file too",
  /itemsLoadedAt = 0\s+forgetItemsFileStamp\(\)/.test(body("onSessionHandoff")), "")
check("the stat runs outside the vault helper, with no session and no bw",
  /\/\/ Not a VaultProcess[^\n]*\n[^\n]*\n\s*Process \{\s+id: itemsFileStatProc\s+clearEnvironment: true\s+environment: [^\n]+\s+stdout: SplitParser \{\s+onRead: function\(line\) \{ root\.itemsFileStatLine = line \}\s+\}\s+onExited: function\(exitCode\) \{ root\.onItemsFileProbed\(exitCode\) \}\s+\}/.test(source)
    && !/\bbw\b(?!-data)/.test(Model.bwDataStatCommand("/f")[2].replace(/for __b in node bw/, "")))

done()
