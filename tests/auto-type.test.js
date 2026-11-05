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
  "stopAutoType", "copyPasswordAndArm", "requestAutoType", "onAutoTypeRead", "typeHere", "onAutoTypeExited",
  "finishAutoType", "screenLockReadingFresh", "armTotpFollowup", "copyTotpAfterAutoType", "notifyTotpCopied"]
function makeVault() {
  const calls = []
  const timer = name => ({ running: false, interval: 0, restart() { this.running = true; calls.push(name + ".restart") },
    stop() { this.running = false } })
  const v = {
    Model, calls, autoTypeEnabled: true, status: "unlocked", session: "held", vaultEpoch: 3, closeOnCopy: true,
    autoTypeItemId: "", autoTypeArmEpoch: -1, autoTypeBusy: false, autoTypeSeq: 0, autoTypePendingText: "",
    autoTypeTypedItemId: "", autoTypeTypedEpoch: -1, autoCopyTotpSec: 3, fetches: [],
    totpFollowupItem: null, totpFollowupActive: false,
    opened: false, sshPrompt: null, pinentryActive: false, vaultHelperActive: true,
    // A screen-lock reading from just now.
    screenIsLocked: false, screenLockCheckedAt: Date.now(), screenLockStateProc: { running: false },
    errorMessage: "", flashed: [], notices: [], queries: [], reads: [],
    repromptPending: false, repromptItemId: "", repromptItemName: "", repromptError: "", repromptBusy: false,
    repromptCallback: null, repromptEpoch: -1, repromptVerifiedId: "", repromptActionId: "", detailItem: null,
    items: [
      { id: "a", typeCode: 1, name: "Bank", username: "me", hasPassword: true, secretsHeld: true, reprompt: 0 },
      { id: "r", typeCode: 1, name: "Safe", username: "me", hasPassword: true, secretsHeld: true, reprompt: 1 },
      { id: "c", typeCode: 3, name: "Card", hasPassword: false, secretsHeld: true, reprompt: 0 },
      { id: "x", typeCode: 1, name: "Nopw", username: "me", hasPassword: false, secretsHeld: true, reprompt: 0 },
      { id: "t", typeCode: 1, name: "Mail", username: "me", hasPassword: true, hasTotp: true, secretsHeld: true, reprompt: 0 }
    ],
    autoTypeArmTimer: timer("arm"), autoTypeWatchdog: timer("watchdog"),
    totpFollowupTimer: timer("totpFollowup"), autoTotpTimer: timer("autoTotp"),
    fetchTotp(id, copyWhenReady) { v.fetches.push([id, Boolean(copyWhenReady)]) },
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
  check("a lock drops it with the vault's secrets, and stops a type in flight",
    /disarmAutoType\(\)\s*stopAutoType\(\)/.test(body("dropVaultSecrets"))
      && /autoTypePendingText = ""/.test(body("stopAutoType")), body("dropVaultSecrets"))
  check("it lasts autoTypeArmMs, then is dropped",
    /id: autoTypeArmTimer\s*interval: Model\.autoTypeArmMs\(\)\s*repeat: false\s*onTriggered: root\.disarmAutoType\(\)/.test(service), "")
  check("turning auto-type off drops it", /onAutoTypeEnabledChanged: \{\s*if \(!autoTypeEnabled\) disarmAutoType\(\)/.test(service), "")
}

// --- the TOTP code, around a type --------------------------------------------------------

const totpNotices = v => v.notices.filter(c => c[0] === "omarchy-notification-send" && c.indexOf("TOTP Code Copied") >= 0)
const totpCopies = v => v.fetches.filter(f => f[1])
{
  const v = makeVault()
  v.copyPasswordAndArm(item(v, "t"))
  check("arming a login with TOTP arms Enter's follow-up too: Enter again copies the code",
    v.totpFollowupItem && v.totpFollowupItem.id === "t" && v.totpFollowupActive && v.calls.indexOf("totpFollowup.restart") >= 0
      && JSON.stringify(v.fetches) === '[["t",false]]', JSON.stringify({ calls: v.calls, fetches: v.fetches }))
  check("and schedules the autoCopyTotpSec auto-copy",
    v.autoTotpTimer.running && v.autoTotpTimer.interval === 3000, JSON.stringify(v.autoTotpTimer))
  const w = makeVault()
  w.copyPasswordAndArm(item(w, "a"))
  check("a login without TOTP arms no follow-up",
    w.totpFollowupItem === null && !w.totpFollowupActive && !w.autoTotpTimer.running && w.fetches.length === 0, "")
  const off = makeVault()
  off.autoCopyTotpSec = 0
  off.copyPasswordAndArm(item(off, "t"))
  check("with the auto-copy off, the follow-up is armed but nothing is scheduled",
    off.totpFollowupActive && !off.autoTotpTimer.running, "")
  const r = makeVault()
  item(r, "t").reprompt = 1
  r.copyPasswordAndArm(item(r, "t"))
  check("an item that asks for the master password arms no follow-up before the prompt is answered",
    r.repromptPending && r.totpFollowupItem === null && r.fetches.length === 0, "")
}
check("Enter's copy and the arm share one follow-up, and one TOTP notice",
  /copyPasswordNow\(item\)\s*armTotpFollowup\(item\)/.test(body("smartCopy"))
    && /root\.copyPasswordNow\(item, [^\n]*\n[^\n]*\n\s*root\.armTotpFollowup\(item\)/.test(body("copyPasswordAndArm"))
    && (service.match(/TOTP Code Copied/g) || []).length === 1
    && /root\.notifyTotpCopied\(\)/.test(service.slice(service.indexOf("id: autoTotpTimer"), service.indexOf("id: autoTotpTimer") + 500)),
  body("smartCopy"))
{
  const v = makeVault()
  v.copyPasswordAndArm(item(v, "t"))
  eq("a TOTP login types", v.requestAutoType(), "started")
  check("nothing is copied before the helper says the type worked", totpCopies(v).length === 0 && totpNotices(v).length === 0
    && v.autoTotpTimer.running, JSON.stringify(v.fetches))
  v.queries[0].cb(true, true)
  check("after it, a fresh TOTP code is copied once, and the desktop notice says so",
    JSON.stringify(totpCopies(v)) === '[["t",true]]' && totpNotices(v).length === 1 && v.flashed.indexOf("Auto-typed") >= 0,
    JSON.stringify({ fetches: v.fetches, notices: v.notices }))
  check("the arm's pending auto-copy is stopped, so an older code cannot land over it", !v.autoTotpTimer.running, "")
  check("and the typed login is forgotten", v.autoTypeTypedItemId === "" && v.autoTypeTypedEpoch === -1, v.autoTypeTypedItemId)
  v.queries[0].cb(true, true)
  check("a repeated answer copies nothing more", totpCopies(v).length === 1, JSON.stringify(v.fetches))

  const h = makeVault()
  h.vaultHelperActive = false
  item(h, "t").password = "hunter2"
  h.copyPasswordAndArm(item(h, "t"))
  h.requestAutoType()
  h.onAutoTypeExited(0)
  check("without the helper too, after wtype exits 0", JSON.stringify(totpCopies(h)) === '[["t",true]]' && totpNotices(h).length === 1,
    JSON.stringify(h.fetches))
  const hf = makeVault()
  hf.vaultHelperActive = false
  item(hf, "t").password = "hunter2"
  hf.copyPasswordAndArm(item(hf, "t"))
  hf.requestAutoType()
  hf.onAutoTypeExited(1)
  check("but not after wtype fails", totpCopies(hf).length === 0 && totpNotices(hf).length === 0, JSON.stringify(hf.fetches))

  const off = makeVault()
  off.autoCopyTotpSec = 0
  off.copyPasswordAndArm(item(off, "t"))
  off.requestAutoType()
  off.queries[0].cb(true, true)
  check("autoCopyTotpSec 0 turns it off after a type too", totpCopies(off).length === 0 && totpNotices(off).length === 0,
    JSON.stringify(off.fetches))

  const plain = makeVault()
  plain.copyPasswordAndArm(item(plain, "a"))
  plain.requestAutoType()
  plain.queries[0].cb(true, true)
  check("a login without TOTP copies nothing after its type", totpCopies(plain).length === 0 && totpNotices(plain).length === 0, "")

  for (const reason of ["missing", "stopped", "failed"]) {
    const f = makeVault()
    f.copyPasswordAndArm(item(f, "t"))
    f.requestAutoType()
    f.queries[0].cb(false, reason)
    check(`a type that ended "${reason}" copies no code`, totpCopies(f).length === 0 && totpNotices(f).length === 0
      && f.autoTypeTypedItemId === "", JSON.stringify(f.fetches))
  }
  const late = makeVault()
  late.copyPasswordAndArm(item(late, "t"))
  late.requestAutoType()
  late.autoTypeSeq += 1 // the watchdog gave up on it
  late.finishAutoType(false, "timeout")
  late.queries[0].cb(true, true)
  check("nor one the watchdog gave up on, when the helper's late success comes in", totpCopies(late).length === 0
    && totpNotices(late).length === 0, JSON.stringify(late.fetches))

  const lock = makeVault()
  lock.copyPasswordAndArm(item(lock, "t"))
  lock.requestAutoType()
  lock.stopAutoType() // a lock, logout or account switch (dropVaultSecrets())
  lock.vaultEpoch += 1
  lock.status = "locked"
  lock.queries[0].cb(true, true)
  check("a lock between the arm and the type's end copies nothing, and forgets the login",
    totpCopies(lock).length === 0 && totpNotices(lock).length === 0 && lock.autoTypeTypedItemId === "", JSON.stringify(lock.fetches))
  const gen = makeVault()
  gen.copyPasswordAndArm(item(gen, "t"))
  gen.requestAutoType()
  gen.vaultEpoch += 1
  gen.finishAutoType(true, "")
  check("a success reported into another vault generation copies nothing", totpCopies(gen).length === 0
    && totpNotices(gen).length === 0, JSON.stringify(gen.fetches))
  check("the typed login is dropped with a type in flight, which a lock stops",
    /autoTypeTypedItemId = ""/.test(body("stopAutoType")) && /stopAutoType\(\)/.test(body("dropVaultSecrets")), body("stopAutoType"))
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
  check("its message covers the helper and the shell's own wtype and bw alike",
    /timed out/.test(Model.autoTypeFailureMessage("timeout")), Model.autoTypeFailureMessage("timeout"))
}
{
  // The helper interrupted the type (a `forget` from a lock, logout or switch,
  // or its shutdown): the lock explains itself, so nothing else is said.
  const v = makeVault()
  v.copyPasswordAndArm(item(v, "a"))
  v.requestAutoType()
  v.queries[0].cb(false, "stopped")
  check("a type the helper stopped ends quietly: busy released, no error, no notification",
    !v.autoTypeBusy && !v.autoTypeWatchdog.running && v.errorMessage === "" && v.notices.length === 0
      && v.flashed.indexOf("Auto-typed") === -1, JSON.stringify({ error: v.errorMessage, notices: v.notices }))
  check("though the message table knows the reason",
    /stopped/.test(Model.autoTypeFailureMessage("stopped"))
      && Model.autoTypeFailureMessage("stopped") !== Model.autoTypeFailureMessage("other"), Model.autoTypeFailureMessage("stopped"))
}

// --- the screen-lock reading ----------------------------------------------------------

{
  // Only the poll refreshes screenIsLocked, and with lockOnScreenLock off it
  // used to run only for the SSH agent: a stale false let a type land on the
  // lock screen. A reading older than a few polls, or none, counts as locked.
  const stale = Date.now() - Model.screenLockPollMs() * 4 - 1
  for (const [what, at] of [["stale", stale], ["absent", 0]]) {
    const v = makeVault()
    v.copyPasswordAndArm(item(v, "a"))
    v.screenLockCheckedAt = at
    check(`a ${what} reading is refused as the screen locked, and the arm kept for the next press`,
      v.requestAutoType() === "screen-locked" && v.autoTypeArmed() && !v.autoTypeBusy && v.queries.length === 0,
      JSON.stringify({ armed: v.autoTypeArmed(), busy: v.autoTypeBusy }))
  }
  const v = makeVault()
  v.copyPasswordAndArm(item(v, "a"))
  v.screenLockCheckedAt = Date.now() - Model.screenLockPollMs() * 4 + 500
  eq("a fresh reading of an unlocked screen types", v.requestAutoType(), "started")
  const w = makeVault()
  w.copyPasswordAndArm(item(w, "a"))
  check("arming takes a reading at once, so the first press is not refused as stale",
    w.screenLockStateProc.running === true, "")
  check("the poll runs while an arm is live, whatever the lock-on-screen-lock setting",
    /id: screenLockPoll[\s\S]{0,600}running: \(root\.lockOnScreenLock && root\.status === "unlocked"\) \|\| root\.sshAgentGateOpen\s*\|\| \(root\.autoTypeEnabled && root\.autoTypeItemId !== ""\)/.test(service), "")
  check("the SSH agent's prompts and auto-type share the one freshness rule",
    /screenLockReadingFresh\(\)/.test(body("sshAgentMayPrompt")) && /screenLockReadingFresh\(\)/.test(body("requestAutoType"))
      && !/screenLockCheckedAt/.test(body("sshAgentMayPrompt")), body("sshAgentMayPrompt"))
}

// --- a lock during a type ---------------------------------------------------------------

{
  const v = makeVault()
  v.copyPasswordAndArm(item(v, "a"))
  v.requestAutoType()
  v.stopAutoType()
  check("a lock ends a type the helper is doing: busy released, watchdog stopped",
    !v.autoTypeBusy && !v.autoTypeWatchdog.running, "")
  v.queries[0].cb(true, true)
  check("and the helper's late answer is ignored", v.flashed.indexOf("Auto-typed") === -1 && v.errorMessage === "", v.flashed.join())
  const w = makeVault()
  w.vaultHelperActive = false
  item(w, "a").password = "hunter2"
  w.copyPasswordAndArm(item(w, "a"))
  w.requestAutoType()
  w.stopAutoType()
  check("without the helper, wtype is killed and the text it was owed dropped",
    w.autoTypeProc.running === false && w.autoTypePendingText === "" && !w.autoTypeBusy, JSON.stringify(w.autoTypeProc))
  w.onAutoTypeExited(143)
  check("the killed wtype's exit is not reported as a failure",
    w.errorMessage === "" && w.notices.length === 0, w.errorMessage)
}

// --- the watchdog without the helper -----------------------------------------------------

{
  const v = makeVault()
  v.vaultHelperActive = false
  item(v, "a").password = "hunter2"
  v.copyPasswordAndArm(item(v, "a"))
  v.requestAutoType()
  check("wtype from the shell runs under the watchdog too", v.calls.indexOf("watchdog.restart") >= 0, v.calls.join())
  const w = makeVault()
  w.vaultHelperActive = false
  w.copyPasswordAndArm(item(w, "a"))
  w.requestAutoType()
  check("and so does the bw get password before it", w.calls.indexOf("watchdog.restart") >= 0 && w.autoTypeReadProc.running, w.calls.join())
  check("the watchdog kills a stuck read or wtype rather than leaving the type busy",
    /if \(autoTypeReadProc\.running\) autoTypeReadProc\.running = false\s*if \(autoTypeProc\.running\) autoTypeProc\.running = false\s*root\.autoTypeSeq \+= 1\s*root\.finishAutoType\(false, "timeout"\)/.test(service), "")
  // As the watchdog does, then the killed processes exit.
  w.autoTypeSeq += 1
  w.finishAutoType(false, "timeout")
  const reported = w.notices.length
  w.onAutoTypeRead(137, "", "a")
  w.onAutoTypeExited(143)
  check("the exits of what it killed add no second report",
    w.notices.length === reported && reported === 1 && !w.autoTypeBusy && w.calls.indexOf("scrub") >= 0, JSON.stringify(w.notices))
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
  x.copyPasswordAndArm(item(x, "a"))
  x.requestAutoType()
  x.onAutoTypeRead(0, "hunter2", "a")
  x.onAutoTypeExited(127)
  check("exit 127 is a missing wtype", x.autoTypeProc.running && /not installed/.test(x.errorMessage), x.errorMessage)
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

// --- the panel --------------------------------------------------------------------------

const view = read("Panel.qml")
const interceptor = view.slice(view.indexOf("id: shortcutInterceptor"), view.indexOf("PanelKeyCatcher {", view.indexOf("id: shortcutInterceptor")))
check("the catcher's Ctrl+C arms only while the catcher has the keys, through the one Panel function",
  /if \(!keyCatcher\.blocked && root\.armAutoTypeFromKey\(event\)\) \{\s*event\.accepted = true\s*return\s*\}/.test(interceptor)
    && (interceptor.match(/Qt\.Key_C/g) || []).length === 0, interceptor)
check("the catcher stays blocked while the search box (or any field) has focus",
  /blocked: repromptConfirm\.shown\s*\|\| searchField\.activeFocus\s*\|\| emailField\.activeFocus\s*\|\| loginPassField\.activeFocus/.test(view), "")

// The search box and the catcher share armAutoTypeFromKey(); its handler and
// the function run here against a stand-in vault and field.
const searchBox = src.slice(src.indexOf("id: searchField"), src.indexOf("id: clearSearchBtn"))
function handlerText(block, head) {
  const start = block.indexOf(head)
  if (start < 0) return ""
  let depth = 0
  for (let i = block.indexOf("{", start); i < block.length; i++) {
    if (block[i] === "{") depth++
    else if (block[i] === "}" && --depth === 0) return block.slice(block.indexOf("function", start), i + 1)
  }
  return ""
}
const searchKeys = handlerText(searchBox, "Keys.onPressed: function(event)")
const Qt = { NoModifier: 0, ShiftModifier: 0x02000000, ControlModifier: 0x04000000, AltModifier: 0x08000000,
  KeypadModifier: 0x20000000, Key_C: 0x43, Key_V: 0x56 }
function searchBoxWith(opts = {}) {
  const r = {
    autoTypeEnabled: opts.autoTypeEnabled !== false, currentScreen: opts.screen || "main", detailItem: opts.detailItem || null,
    filteredItems: opts.items || [{ id: "top", isSuggested: true }, { id: "next" }], selectedIndex: opts.selectedIndex || 0,
    armed: [], alt: [],
    getSelectedItem() { return r.filteredItems[r.selectedIndex] || null },
    copyPasswordAndArm(item) { r.armed.push(item.id); return opts.armResult !== false },
    runAltShortcut(t) { r.alt.push(t); return true }
  }
  r.armAutoTypeFromKey = new Function("root", "Qt", body("armAutoTypeFromKey") + "\nreturn armAutoTypeFromKey")(r, Qt)
  const field = { selectedText: opts.selected || "" }
  const handler = new Function("root", "Qt", "searchField", "return " + searchKeys)(r, Qt, field)
  r.press = (modifiers, key, text) => {
    const event = { modifiers, key, text: text || "", accepted: false }
    handler(event)
    return event.accepted
  }
  return r
}
check("the search box has its own key handler, and it calls the shared function",
  searchKeys !== "" && /searchField\.selectedText === "" && root\.armAutoTypeFromKey\(event\)/.test(searchKeys)
    && /root\.copyPasswordAndArm\(picked\)/.test(body("armAutoTypeFromKey"))
    && /onScreen === "main" \? root\.getSelectedItem\(\)/.test(body("armAutoTypeFromKey")), searchKeys)
{
  const v = searchBoxWith()
  check("Ctrl+C in the search box, nothing selected: the highlighted row (the top suggestion) is armed",
    v.press(Qt.ControlModifier, Qt.Key_C, "\u0003") === true && v.armed.join() === "top", v.armed.join())
  const w = searchBoxWith({ selectedIndex: 1 })
  check("and after moving the highlight, the row it is on",
    w.press(Qt.ControlModifier, Qt.Key_C) === true && w.armed.join() === "next", w.armed.join())
  const k = searchBoxWith()
  check("the keypad modifier does not count as another key held",
    k.press(Qt.ControlModifier | Qt.KeypadModifier, Qt.Key_C) === true && k.armed.join() === "top", k.armed.join())
  const sel = searchBoxWith({ selected: "bank" })
  check("with text selected it is the box's own copy: not taken, nothing armed",
    sel.press(Qt.ControlModifier, Qt.Key_C) === false && sel.armed.length === 0, sel.armed.join())
  for (const [what, mods, key] of [["Ctrl+Shift+C", Qt.ControlModifier | Qt.ShiftModifier, Qt.Key_C],
      ["Ctrl+Alt+C", Qt.ControlModifier | Qt.AltModifier, Qt.Key_C], ["a plain c", Qt.NoModifier, Qt.Key_C],
      ["Ctrl+V", Qt.ControlModifier, Qt.Key_V]]) {
    const x = searchBoxWith()
    // Ctrl+Alt+C is Alt+c to the box (copy username), as before.
    const taken = x.press(mods, key, "c")
    check(`${what} in the search box arms nothing`, x.armed.length === 0 && taken === Boolean(mods & Qt.AltModifier),
      x.armed.join())
  }
  const alt = searchBoxWith()
  check("Alt+letter still runs its shortcut from the box", alt.press(Qt.AltModifier, Qt.Key_C, "c") && alt.alt.join() === "c"
    && alt.armed.length === 0, alt.alt.join())
  const off = searchBoxWith({ autoTypeEnabled: false })
  check("with auto-type off, Ctrl+C is the box's own copy", off.press(Qt.ControlModifier, Qt.Key_C) === false
    && off.armed.length === 0, "")
  const none = searchBoxWith({ items: [] })
  check("an empty list arms nothing and leaves the key", none.press(Qt.ControlModifier, Qt.Key_C) === false
    && none.armed.length === 0, "")
  const card = searchBoxWith({ armResult: false })
  check("a row with nothing to type leaves the key to the box", card.press(Qt.ControlModifier, Qt.Key_C) === false, "")
  const hidden = searchBoxWith({ screen: "edit" })
  check("a hidden search box still holding focus on another screen arms nothing",
    hidden.press(Qt.ControlModifier, Qt.Key_C) === false && hidden.armed.length === 0, hidden.armed.join())
  const detail = searchBoxWith({ screen: "detail", detailItem: { id: "open" } })
  check("on the detail screen the shared function arms the open item, as the catcher's Ctrl+C did",
    detail.press(Qt.ControlModifier, Qt.Key_C) === true && detail.armed.join() === "open", detail.armed.join())
}
check("LineField hands its keys to the field's own handler before the editor's copy (tests/qml/tst_search_ctrl_c.qml)",
  /Keys\.priority: Keys\.BeforeItem\s*Keys\.forwardTo: \[root, keySink\]/.test(read("LineField.qml"))
    && /property alias selectedText: editor\.selectedText/.test(read("LineField.qml")), "")
check("Enter in the search box acts on the same row",
  /Keys\.onReturnPressed: root\.smartEnter\(root\.getSelectedItem\(\)\)/.test(searchBox), "")
const row = view.slice(view.indexOf("id: actionButtonsRow"), view.indexOf("id: rowMouseArea"))
const armButton = row.slice(row.indexOf("arm auto-type") - 300, row.indexOf("arm auto-type") + 200)
check("the row's button is shown only with auto-type on, says what it does, and arms after any prompt",
  /visible: root\.vault\.autoTypeEnabled && Model\.isLoginItem\(itemRow\.itemData\) && itemRow\.itemData\.hasPassword/.test(armButton)
    && /tooltipText: "Copy password and arm auto-type \(Ctrl\+C\)"/.test(armButton)
    && /onClicked: root\.vault\.copyPasswordAndArm\(itemRow\.itemData\)/.test(armButton), armButton)
check("the password button keeps its place, first in the row",
  row.indexOf('tooltipText: "Copy password (Enter / y)"') < row.indexOf("arm auto-type")
    && row.indexOf("arm auto-type") < row.indexOf('tooltipText: "Copy username (u)"'), "")

done()
