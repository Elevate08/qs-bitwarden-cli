#!/usr/bin/env node
// Auto-type (off by default): the setting and its confirmation, the wtype
// dependency, arming from the panel, and the `autoType` IPC. The vault's own
// functions run here against a stand-in vault (the state they read and
// write, and recorded calls); the wiring is checked in the source. Nothing
// here starts wtype: the helper's typing is covered by its Rust tests,
// against a stand-in wtype.
//
//   node tests/auto-type.test.js

const { createSuite, functionBody, loadModule, read, readPluginSource } = require("./harness")

const Model = loadModule()
const src = readPluginSource("Panel.qml")
const service = read("Service.qml")
const body = name => functionBody(src, name)
const { check, eq, done } = createSuite("auto-type")

// Runs `names` from Service.qml with `v` as their scope (and as `root`).
function bind(v, names) {
  v.root = v
  const make = new Function("root", "with (root) {\n" + names.map(body).join("\n")
    + "\nreturn {" + names.map(n => `${n}: ${n}`).join(", ") + "} }")
  Object.assign(v, make(v))
  return v
}

// --- the setting -------------------------------------------------------------------

const entry = Model.settingSchemaEntry("autoTypeEnabled")
const manifest = JSON.parse(read("manifest.json")).barWidget
const listed = manifest.schema.find(e => e.key === "autoTypeEnabled")
check("auto-type is off by default, in the settings screen and the manifest",
  entry && entry.defaultValue === false && entry.type === "bool"
    && listed && listed.defaultValue === false && listed.type === "boolean"
    && manifest.defaults.autoTypeEnabled === false,
  JSON.stringify({ entry, listed, defaults: manifest.defaults.autoTypeEnabled }))
check("the service reads it false-safe",
  /readonly property bool autoTypeEnabled: Model\.boolSetting\("autoTypeEnabled", setting\("autoTypeEnabled", false\)\)/
    .test(service), "")
for (const [where, text] of [["settings screen", entry.description], ["manifest", listed.description]]) {
  check(`the ${where} says what it risks and what it needs`,
    /Off by default/.test(text) && /whatever window has focus/.test(text) && /any program running as you/.test(text)
      && /Needs wtype/.test(text) && text.indexOf(Model.autoTypeArmMs() / 1000 + " seconds") >= 0, text)
}
eq("the manifest and the settings screen describe it alike", listed.description, entry.description)
check("turning it on asks once more", /Press again to turn it on/.test(entry.confirm || ""), String(entry.confirm))

{
  const names = ["toggleBoolSetting", "settingNote"]
  const v = bind({
    settingConfirmKey: "", writes: [], values: {}, fingerprintUnlock: false, fingerprintStored: false,
    autoTypeEnabled: false, depsChecked: false, dependencies: { items: [] }, Model,
    settingValue(e) { return Boolean(v.values[e.key]) },
    writeSetting(key, value, type) { v.writes.push([key, value, type]) }
  }, names)
  v.toggleBoolSetting(entry)
  check("the first press only asks, and the row says why",
    v.writes.length === 0 && v.settingNote(entry) === entry.confirm, JSON.stringify(v.writes))
  v.toggleBoolSetting(entry)
  eq("the second turns it on", JSON.stringify(v.writes), JSON.stringify([["autoTypeEnabled", true, "bool"]]))
  check("and the question is gone", v.settingNote(entry) === "", v.settingNote(entry))
  v.values.autoTypeEnabled = true
  v.writes = []
  v.toggleBoolSetting(entry)
  eq("turning it off asks nothing", JSON.stringify(v.writes), JSON.stringify([["autoTypeEnabled", false, "bool"]]))
  const plain = Model.settingSchemaEntry("closeOnCopy")
  v.writes = []
  v.toggleBoolSetting(plain)
  eq("other switches flip at once", JSON.stringify(v.writes), JSON.stringify([["closeOnCopy", true, "bool"]]))
}
check("both the switch and the keyboard go through the confirmation",
  /if \(e\.type === "bool"\) toggleBoolSetting\(e\)/.test(body("activateSettingRow"))
    && /root\.vault\.toggleBoolSetting\(modelData\)/.test(read("Panel.qml"))
    && !/root\.vault\.writeSetting\(modelData\.key, !checked, "bool"\)/.test(read("Panel.qml")), "")
check("a question left unanswered is dropped when the cursor moves or the screen opens",
  /settingConfirmKey = ""/.test(body("moveSettingsCursor")) && /settingConfirmKey = ""/.test(body("openSettings")), "")

// --- wtype ---------------------------------------------------------------------------

check("the dependency probe is told whether auto-type is on",
  (service.match(/Model\.parseDependencies\([^\n]*dependencyFeatures\(\)\)/g) || []).length === 2
    && /return \{ autoType: autoTypeEnabled \}/.test(body("dependencyFeatures")), body("dependencyFeatures"))
check("and asked again when it is turned on or off",
  /onAutoTypeEnabledChanged: \{[\s\S]{0,200}if \(depsChecked\) checkDependencies\(\)/.test(service), "")
{
  const v = bind({
    settingConfirmKey: "", autoTypeEnabled: true, depsChecked: true, fingerprintUnlock: false, Model,
    dependencies: Model.parseDependencies("bw=1\njq=1\nwtype=0\nomarchy=1", null, { autoType: true })
  }, ["settingNote"])
  check("auto-type on without wtype says so on its row", /wtype is not installed/.test(v.settingNote(entry)), "")
  v.dependencies = Model.parseDependencies("bw=1\njq=1\nwtype=1\nomarchy=1", null, { autoType: true })
  eq("and stops once it is installed", v.settingNote(entry), "")
}

// --- arming --------------------------------------------------------------------------

const flowNames = ["itemNeedsReprompt", "repromptSatisfied", "withReprompt", "autoTypeArmed", "disarmAutoType",
  "copyPasswordAndArm", "requestAutoType", "onAutoTypeRead", "typeHere", "onAutoTypeExited", "finishAutoType"]
function makeVault() {
  const calls = []
  const timer = name => ({ running: false, restart() { this.running = true; calls.push(name + ".restart") },
    stop() { this.running = false } })
  const v = {
    Model, calls, autoTypeEnabled: true, status: "unlocked", session: "held", vaultEpoch: 3, closeOnCopy: true,
    autoTypeItemId: "", autoTypeArmEpoch: -1, autoTypeBusy: false, autoTypeSeq: 0, autoTypePendingText: "",
    opened: false, sshPrompt: null, pinentryActive: false, screenIsLocked: false, vaultHelperActive: true,
    errorMessage: "", flashed: [], notices: [], queries: [], reads: [],
    repromptPending: false, repromptItemId: "", repromptItemName: "", repromptError: "", repromptBusy: false,
    repromptCallback: null, repromptEpoch: -1, repromptVerifiedId: "", repromptActionId: "", detailItem: null,
    items: [
      { id: "a", typeCode: 1, name: "Bank", username: "me", hasPassword: true, secretsHeld: true, reprompt: 0 },
      { id: "r", typeCode: 1, name: "Safe", username: "me", hasPassword: true, secretsHeld: true, reprompt: 1 },
      { id: "c", typeCode: 3, name: "Card", hasPassword: false, secretsHeld: true, reprompt: 0 },
      { id: "x", typeCode: 1, name: "Nopw", username: "me", hasPassword: false, secretsHeld: true, reprompt: 0 }
    ],
    autoTypeArmTimer: timer("arm"), autoTypeWatchdog: timer("watchdog"),
    autoTypeProc: { running: false, stdinEnabled: false, command: [] },
    autoTypeReadProc: { running: false, command: [], itemId: "" },
    Quickshell: { execDetached(cmd) { v.notices.push(cmd) } },
    closeFilterGroup() {},
    close() { calls.push("close") },
    copyPasswordNow(item, notice) { calls.push("copy:" + item.id + ":" + notice) },
    flashNotification(m) { v.flashed.push(m) },
    resetAutoLockTimer() {},
    vaultQuery(type, fields, cb) { v.queries.push({ type, fields, cb }) },
    beginVaultRead(name) { v.reads.push(name) },
    vaultReadIsStale() { return v.stale === true },
    clearProcessCollectorSoon(proc) { calls.push("scrub") }
  }
  return bind(v, flowNames)
}
const item = (v, id) => v.items.find(i => i.id === id)

{
  const v = makeVault()
  check("Ctrl+C on a login copies and arms it, then closes the panel",
    v.copyPasswordAndArm(item(v, "a")) === true && v.autoTypeArmed() && v.autoTypeItemId === "a"
      && v.calls.indexOf("arm.restart") >= 0 && v.calls.indexOf("close") >= 0
      && /^copy:a:Password copied; auto-type armed for 30 s$/.test(v.calls.find(c => c.indexOf("copy:") === 0)),
    v.calls.join())
  for (const id of ["c", "x"]) {
    const w = makeVault()
    check(`nothing to type, nothing armed (${item(w, id).name})`,
      w.copyPasswordAndArm(item(w, id)) === false && !w.autoTypeArmed() && w.calls.length === 0, w.calls.join())
  }
  const off = makeVault()
  off.autoTypeEnabled = false
  check("with auto-type off, nothing is armed", off.copyPasswordAndArm(item(off, "a")) === false && !off.autoTypeArmed(), "")
}
{
  const v = makeVault()
  check("an item that asks for the master password asks before it is armed",
    v.copyPasswordAndArm(item(v, "r")) === true && v.repromptPending && !v.autoTypeArmed() && v.calls.length === 0,
    v.calls.join())
  v.repromptPending = false
  v.repromptCallback = null
  check("so a cancelled prompt leaves nothing armed and copies nothing", !v.autoTypeArmed() && v.calls.length === 0, "")
  const w = makeVault()
  w.copyPasswordAndArm(item(w, "r"))
  w.repromptActionId = "r"
  w.repromptCallback()
  check("and an accepted one arms and copies", w.autoTypeArmed() && w.calls.some(c => c.indexOf("copy:r") === 0), w.calls.join())
}
{
  const v = makeVault()
  v.copyPasswordAndArm(item(v, "a"))
  v.vaultEpoch = 4
  check("an arm belongs to the vault it was made in", !v.autoTypeArmed(), "")
  check("a lock drops it with the vault's secrets", /disarmAutoType\(\)/.test(body("dropVaultSecrets"))
    && /autoTypePendingText = ""/.test(body("dropVaultSecrets")), body("dropVaultSecrets"))
  check("it lasts autoTypeArmMs, then is dropped",
    /id: autoTypeArmTimer\s*interval: Model\.autoTypeArmMs\(\)\s*repeat: false\s*onTriggered: root\.disarmAutoType\(\)/.test(service), "")
  check("turning auto-type off drops it", /onAutoTypeEnabledChanged: \{\s*if \(!autoTypeEnabled\) disarmAutoType\(\)/.test(service), "")
}

// --- the IPC --------------------------------------------------------------------------

check("the IPC answers with requestAutoType()'s result",
  /function autoType\(\): string \{ return root\.requestAutoType\(\) \}/.test(service), "")
{
  const v = makeVault()
  v.autoTypeEnabled = false
  eq("off: disabled", v.requestAutoType(), "disabled")
  v.autoTypeEnabled = true
  v.status = "locked"
  eq("locked: locked", v.requestAutoType(), "locked")
  v.status = "unlocked"
  eq("nothing armed: not-armed", v.requestAutoType(), "not-armed")
  v.copyPasswordAndArm(item(v, "a"))
  v.opened = true
  check("the panel open: refused, the arm kept, and the panel says why",
    v.requestAutoType() === "panel-open" && v.autoTypeArmed() && /Close the panel/.test(v.errorMessage), v.errorMessage)
  v.opened = false
  for (const [k, val] of [["sshPrompt", {}], ["pinentryActive", true]]) {
    v[k] = val
    eq(`${k}: refused, it has the keyboard`, v.requestAutoType(), "panel-open")
    v[k] = k === "sshPrompt" ? null : false
  }
  v.screenIsLocked = true
  eq("the screen locked: refused", v.requestAutoType(), "screen-locked")
  v.screenIsLocked = false
  eq("armed: started", v.requestAutoType(), "started")
  check("the helper types it; the shell asks by id only",
    v.queries.length === 1 && v.queries[0].type === "autoType" && JSON.stringify(v.queries[0].fields) === '{"id":"a"}'
      && v.autoTypeProc.running === false && v.autoTypeReadProc.running === false, JSON.stringify(v.queries))
  check("one type per arm", !v.autoTypeArmed() && v.autoTypeItemId === "", "")
  v.copyPasswordAndArm(item(v, "a"))
  eq("a second while it types: busy", v.requestAutoType(), "busy")
  check("success only from the helper's answer", v.flashed.indexOf("Auto-typed") === -1 && v.autoTypeBusy, "")
  v.queries[0].cb(true, true)
  check("which ends it", !v.autoTypeBusy && v.flashed.indexOf("Auto-typed") >= 0 && v.notices.length === 0, "")
}
{
  const v = makeVault()
  v.copyPasswordAndArm(item(v, "a"))
  v.requestAutoType()
  v.queries[0].cb(false, "missing")
  check("a failure says why, in the panel and as a desktop notification",
    !v.autoTypeBusy && /wtype, which is not installed/.test(v.errorMessage)
      && v.notices.length === 1 && v.notices[0][0] === "notify-send" && v.notices[0].indexOf(v.errorMessage) >= 0,
    JSON.stringify(v.notices))
  const w = makeVault()
  w.copyPasswordAndArm(item(w, "a"))
  w.requestAutoType()
  w.autoTypeSeq += 1 // the watchdog gave up on it
  w.finishAutoType(false, "timeout")
  w.queries[0].cb(true, true)
  check("an answer after the watchdog gave up is ignored", w.flashed.indexOf("Auto-typed") === -1, w.flashed.join())
  check("the watchdog moves the sequence on before it reports",
    /root\.autoTypeSeq \+= 1\s*root\.finishAutoType\(false, "timeout"\)/.test(service), "")
}
{
  const v = makeVault()
  item(v, "a").secretsHeld = false
  v.copyPasswordAndArm(item(v, "a"))
  check("with the helper up, an item it does not hold is not read with bw",
    v.requestAutoType() === "failed" && v.autoTypeReadProc.running === false && v.queries.length === 0
      && /does not hold this item/.test(v.errorMessage), v.errorMessage)
  const w = makeVault()
  w.copyPasswordAndArm(item(w, "a"))
  w.items = []
  check("an armed item since removed is not typed", w.requestAutoType() === "failed" && !w.autoTypeBusy, "")
}

// --- without the helper ---------------------------------------------------------------

{
  const v = makeVault()
  v.vaultHelperActive = false
  item(v, "a").password = "hunter2"
  v.copyPasswordAndArm(item(v, "a"))
  v.requestAutoType()
  check("a password held in the shell goes to wtype's stdin, not its argv",
    v.autoTypeProc.running && v.autoTypeProc.stdinEnabled && v.autoTypePendingText === "me\thunter2"
      && JSON.stringify(v.autoTypeProc.command) === JSON.stringify(Model.autoTypeCommand())
      && v.autoTypeProc.command.join(" ").indexOf("hunter2") === -1, JSON.stringify(v.autoTypeProc))
  v.onAutoTypeExited(0)
  check("and is dropped when wtype is done", v.autoTypePendingText === "" && v.flashed.indexOf("Auto-typed") >= 0, "")
  check("it is written and dropped as wtype starts",
    /onStarted: \{\s*write\(root\.autoTypePendingText\)\s*root\.autoTypePendingText = ""\s*stdinEnabled = false/.test(service), "")
  const w = makeVault()
  w.vaultHelperActive = false
  w.copyPasswordAndArm(item(w, "a"))
  w.requestAutoType()
  check("otherwise one bw get password, stamped with the vault generation",
    w.autoTypeReadProc.running && w.reads.join() === "autoType" && w.autoTypeReadProc.itemId === "a"
      && JSON.stringify(w.autoTypeReadProc.command) === JSON.stringify(Model.getPasswordCommand("a", 1)), "")
  w.stale = true
  w.onAutoTypeRead(0, "hunter2", "a")
  check("a read that outlived a lock types nothing", !w.autoTypeProc.running && !w.autoTypeBusy
    && w.calls.indexOf("scrub") >= 0, "")
  const x = makeVault()
  x.vaultHelperActive = false
  x.copyPasswordAndArm(item(x, "a"))
  x.requestAutoType()
  x.onAutoTypeRead(0, "two\nlines", "a")
  check("a value wtype would press as keys is refused", !x.autoTypeProc.running && /control character/.test(x.errorMessage), x.errorMessage)
  x.onAutoTypeExited(127)
  check("exit 127 is a missing wtype", /not installed/.test(x.errorMessage), x.errorMessage)
}
check("the read's collector is scrubbed on lock with the other secret readers",
  /copyPasswordProc, autoTypeReadProc,/.test(body("secretProcesses")), body("secretProcesses"))

// --- what is typed ---------------------------------------------------------------------

eq("username, Tab, password", Model.autoTypeText("me", "pw").text, "me\tpw")
eq("the password alone without a username", Model.autoTypeText("", "pw").text, "pw")
for (const bad of ["a\nb", "a\tb", "a\rb", "a\bb", "a\u007fb", "a\u001bb", "a\u0085b"]) {
  check(`refused: ${JSON.stringify(bad)}`, Model.autoTypeText("me", bad).reason === "unsafe"
    && Model.autoTypeText(bad, "pw").reason === "unsafe", "")
}
eq("no password, nothing to type", Model.autoTypeText("me", "").reason, "empty")
check("the same wtype run as the helper's, from stdin, in a UTF-8 locale",
  Model.autoTypeCommand()[2] === "LC_ALL=C.UTF-8 exec wtype -s 250 -d 12 -"
    && read("vault/src/main.rs").indexOf('["-s", "250", "-d", "12", "-"]') >= 0, Model.autoTypeCommand().join(" "))
check("no secret is put in an environment or argv for wtype",
  !/QSBW_PASS|QSBW_USER|\| wtype/.test(service), "")

done()
