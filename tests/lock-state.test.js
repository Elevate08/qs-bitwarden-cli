#!/usr/bin/env node
// What the panel must stop doing when the vault is not open.
//
// Three ways it kept going anyway, all of them silent:
//
// 1. The auto-lock countdown ran on a Qt Timer, and Qt schedules on
//    CLOCK_MONOTONIC, which Linux stops while the machine is suspended. A
//    fifteen-minute lock armed just before the lid closed still had fifteen
//    minutes left when the lid opened, so a vault left overnight came back
//    open. The deadline is now kept in wall-clock terms as well.
//
// 2. The minute count behind that countdown came out of shell.json, and
//    nothing validates shell.json. A non-numeric value reached QML as NaN and
//    landed in an `int` property as 0, which is how "never lock" is spelled; a
//    value past the schema's ceiling overflowed Timer.interval into a negative
//    number, which never fires. Both readings were a vault that never locked.
//
// 3. Nothing cancels a `bw` that is already running, so a `bw list items`
//    started a second before the lock finished afterwards and put the whole
//    vault -- passwords and all -- back into a panel that had just dropped it.
//
//   node tests/lock-state.test.js

const fs = require("fs")
const path = require("path")

const Model = {}
new Function("exports", fs.readFileSync(path.join(__dirname, "..", "BitwardenModel.js"), "utf8")
  .replace(/^\.pragma library\s*$/m, "") + `
  exports.intSetting = intSetting
  exports.settingSchemaEntry = settingSchemaEntry
  exports.SETTINGS_SCHEMA = SETTINGS_SCHEMA
  exports.autoLockExpired = autoLockExpired
  exports.autoLockPollMs = autoLockPollMs
  exports.vaultReadIsStale = vaultReadIsStale
  exports.parseItems = parseItems
`)(Model)

let pass = 0
const failures = []
const check = (l, ok, d) => ok ? pass++ : failures.push(`${l}\n    ${d}`)

const panelSrc = fs.readFileSync(path.join(__dirname, "..", "Panel.qml"), "utf8")
const bodyOf = (name) => {
  const start = panelSrc.indexOf(`function ${name}(`)
  if (start === -1) return ""
  let depth = 0
  for (let i = panelSrc.indexOf("{", start); i < panelSrc.length; i++) {
    if (panelSrc[i] === "{") depth++
    else if (panelSrc[i] === "}" && --depth === 0) return panelSrc.slice(start, i + 1)
  }
  return ""
}

// --- 1. The schema is the same on both sides of shell.json ------------------
// The settings screen clamps to SETTINGS_SCHEMA on the way out and the
// marketplace shows manifest.json's min/max, so the two have to agree or the
// clamp on the way back in enforces a range nobody was shown.
const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "manifest.json"), "utf8"))
const manifestEntries = {}
for (const e of manifest.barWidget.schema) manifestEntries[e.key] = e

for (const entry of Model.SETTINGS_SCHEMA) {
  if (entry.type !== "int") continue
  const m = manifestEntries[entry.key]
  check(`manifest declares ${entry.key}`, !!m, JSON.stringify(Object.keys(manifestEntries)))
  if (!m) continue
  check(`${entry.key} min agrees with the manifest`, m.min === entry.min, `${m.min} vs ${entry.min}`)
  check(`${entry.key} max agrees with the manifest`, m.max === entry.max, `${m.max} vs ${entry.max}`)
  check(`${entry.key} default agrees with the manifest`,
    m.defaultValue === entry.defaultValue, `${m.defaultValue} vs ${entry.defaultValue}`)
  check(`${entry.key} default agrees with the widget defaults block`,
    manifest.barWidget.defaults[entry.key] === entry.defaultValue,
    `${manifest.barWidget.defaults[entry.key]} vs ${entry.defaultValue}`)
  // The ceiling exists so the value can be turned into milliseconds and put in
  // a Timer, whose interval is a signed 32-bit int.
  const scale = entry.key === "autoLockMinutes" ? 60 * 1000 : 1000
  check(`${entry.key} max still fits Timer.interval`,
    entry.max * scale <= 2147483647, `${entry.max * scale}`)
}

// --- 2. Reading a setting back out of shell.json ----------------------------
// `omarchy bar set` writes whatever it is handed -- a bare word becomes a JSON
// string, --json stores any number at all -- and the README documents editing
// the file by hand, so every one of these is reachable.
for (const [key, raw, want, why] of [
  ["autoLockMinutes", 15,        15,   "an ordinary value is untouched"],
  ["autoLockMinutes", "30",      30,   "the string form `omarchy bar set` writes without --json"],
  ["autoLockMinutes", 0,         0,    "an explicit 0 still means never"],
  ["autoLockMinutes", "fifteen", 15,   "a word falls back to the default, NOT to 0/never"],
  ["autoLockMinutes", undefined, 15,   "an unset key falls back to the default"],
  ["autoLockMinutes", null,      15,   "a null falls back to the default"],
  ["autoLockMinutes", "",        15,   "an empty string falls back to the default"],
  ["autoLockMinutes", true,      15,   "a boolean falls back to the default"],
  ["autoLockMinutes", 999999,    1440, "a count that would overflow Timer.interval is capped"],
  ["autoLockMinutes", 1e30,      1440, "so is one written in exponential notation"],
  ["autoLockMinutes", -5,        0,    "a negative count clamps to the floor"],
  ["autoLockMinutes", 15.9,      15,   "a fraction truncates rather than reaching the Timer"],
  ["clearClipboardSec", 100000,  300,  "the clipboard timeout has its own ceiling"],
  ["clearClipboardSec", "soon",  30,   "and its own default"],
  ["autoCopyTotpSec", 999,       30,   "so does the TOTP delay"],
  ["autoCopyTotpSec", "off",     3,    "and its default is not 0 either"],
]) {
  const got = Model.intSetting(key, raw)
  check(`intSetting(${key}, ${JSON.stringify(raw)}) -> ${want}: ${why}`, got === want, `got ${got}`)
}

check("every clamped value is a finite integer",
  [undefined, null, "", "x", {}, [], NaN, Infinity, -Infinity, 1e400].every(v => {
    const n = Model.intSetting("autoLockMinutes", v)
    return Number.isInteger(n) && n >= 0 && n <= 1440
  }), "one of the junk values escaped the clamp")

check("the panel reads its int settings through the clamp",
  /autoLockMinutes:\s*Model\.intSetting\("autoLockMinutes"/.test(panelSrc)
    && /clearClipboardSec:\s*Model\.intSetting\("clearClipboardSec"/.test(panelSrc)
    && /autoCopyTotpSec:\s*Model\.intSetting\("autoCopyTotpSec"/.test(panelSrc),
  "expected Model.intSetting() on all three integer settings")

// --- 3. The auto-lock deadline survives a suspend ---------------------------
const t0 = 1700000000000
check("not expired before the window is up",
  Model.autoLockExpired(t0, 15, t0 + 14 * 60000) === false, "expired early")
check("expired the moment the window is up",
  Model.autoLockExpired(t0, 15, t0 + 15 * 60000) === true, "did not expire")

// The bug itself. The shell is frozen across a suspend, so the monotonic Timer
// counts only the seconds either side of it; the wall clock counts the night.
const awakeMsBeforeSuspend = 60 * 1000
const suspendMs = 12 * 60 * 60 * 1000
check("a twelve-hour suspend expires a fifteen-minute window",
  Model.autoLockExpired(t0, 15, t0 + awakeMsBeforeSuspend + suspendMs) === true,
  "the vault would have come back unlocked")
check("the monotonic clock alone would not have noticed",
  awakeMsBeforeSuspend < 15 * 60000, "premise of the test is wrong")

check("zero minutes is the user asking for no auto-lock, not an instant one",
  Model.autoLockExpired(t0, 0, t0 + suspendMs) === false, "locked with auto-lock off")
check("an unarmed window has no deadline to have passed",
  Model.autoLockExpired(0, 15, t0) === false, "locked without ever being armed")
check("junk cannot make it lock, or stop it locking",
  Model.autoLockExpired(NaN, 15, t0) === false
    && Model.autoLockExpired(t0, NaN, t0 + suspendMs) === false
    && Model.autoLockExpired(t0, 15, NaN) === false,
  "a NaN got through")

for (const [minutes, want] of [[15, 30000], [60, 30000], [1, 30000], [0, 30000]]) {
  check(`autoLockPollMs(${minutes}) === ${want}`, Model.autoLockPollMs(minutes) === want,
    String(Model.autoLockPollMs(minutes)))
}
check("the poll never outlasts the window it is watching",
  [1, 5, 15, 1440].every(m => Model.autoLockPollMs(m) <= m * 60000), "poll longer than the window")
check("and never busy-loops",
  [0, 1, 15, 1440].every(m => Model.autoLockPollMs(m) >= 1000), "poll under a second")

check("the panel arms the window in wall-clock terms",
  /autoLockArmedAt\s*=\s*Date\.now\(\)/.test(bodyOf("resetAutoLockTimer")),
  bodyOf("resetAutoLockTimer"))
const watchdog = panelSrc.slice(panelSrc.indexOf("id: autoLockWatchdog"),
  panelSrc.indexOf("id: autoLockWatchdog") + 900)
check("the panel runs a wall-clock watchdog alongside the monotonic timer",
  panelSrc.includes("id: autoLockWatchdog"), "no autoLockWatchdog Timer")
check("the watchdog repeats, or it is just the monotonic timer again",
  /repeat:\s*true/.test(watchdog), watchdog)
check("the watchdog only runs on an unlocked vault",
  /running:\s*root\.status === "unlocked" && root\.autoLockMinutes > 0/.test(watchdog), watchdog)
check("the watchdog asks the wall clock",
  /Model\.autoLockExpired\(root\.autoLockArmedAt, root\.autoLockMinutes, Date\.now\(\)\)/.test(watchdog),
  watchdog)
check("and locks when it has passed",
  /root\.lockVault\(\)/.test(watchdog), watchdog)

// --- 4. A reader that outlived the vault it was reading ---------------------
check("same generation, session still there: fresh",
  Model.vaultReadIsStale(3, 3, true) === false, "rejected a live result")
check("the vault changed hands: stale",
  Model.vaultReadIsStale(3, 4, true) === true, "accepted a result from a previous vault")
check("no session at all: stale whatever the generation says",
  Model.vaultReadIsStale(3, 3, false) === true, "accepted a result into a locked vault")
check("a reader that never recorded a generation is stale, not fresh",
  Model.vaultReadIsStale(undefined, 0, true) === true, "unstamped read treated as fresh")

// Replay of the real sequence, with the panel's own logic standing in for the
// panel. `bw list items` is in flight; the vault locks; the list lands.
function fakePanel() {
  return {
    session: "SESSION-A",
    vaultEpoch: 0,
    readEpochs: {},
    items: [],
    itemsLoadedAt: 0,
    beginVaultRead(name) { this.readEpochs[name] = this.vaultEpoch },
    stale(name) { return Model.vaultReadIsStale(this.readEpochs[name], this.vaultEpoch, !!this.session) },
    loadItems() { this.beginVaultRead("items") },
    onListFinished(raw) {
      if (this.stale("items")) return
      this.items = Model.parseItems(raw)
      this.itemsLoadedAt = 1
    },
    lockVault() { this.session = ""; this.vaultEpoch += 1; this.items = []; this.itemsLoadedAt = 0 },
    unlockAs(token) { this.session = token; this.vaultEpoch += 1 }
  }
}

const vaultA = JSON.stringify([
  { id: "a1", name: "Bank", type: 1, login: { username: "me", password: "hunter2" } }
])
const vaultB = JSON.stringify([
  { id: "b1", name: "Work", type: 1, login: { username: "work", password: "correct-horse" } }
])

let p = fakePanel()
p.loadItems()
p.lockVault()
p.onListFinished(vaultA)
check("a list that lands after the lock does not refill the vault",
  p.items.length === 0, JSON.stringify(p.items))

p = fakePanel()
p.loadItems()
p.lockVault()
p.unlockAs("SESSION-B")     // logged out and back in as somebody else
p.onListFinished(vaultA)
check("nor after a re-login, where it would have been drawn as the new account's",
  p.items.length === 0, JSON.stringify(p.items))
p.loadItems()
p.onListFinished(vaultB)
check("the new account's own list is accepted",
  p.items.length === 1 && p.items[0].id === "b1", JSON.stringify(p.items))
check("and the cache is not marked fresh off a discarded answer",
  fakePanel().itemsLoadedAt === 0, "premise")

// Every reader the panel has, wired at both ends.
for (const [name, starter, handler] of [
  ["items",         "loadItems",          "onListFinished"],
  ["organizations", "loadOrganizations",  "onListOrgsFinished"],
  ["folders",       "loadFolders",        "onListFoldersFinished"],
  ["collections",   "loadOrgCollections", "onOrgCollectionsLoaded"],
  ["detail",        "openDetail",         "onDetailFinished"],
  ["totp",          "fetchTotp",          "onTotpFinished"],
  ["sends",         "loadSends",          "onSendsLoaded"],
]) {
  check(`${starter}() records the vault generation`,
    new RegExp(`beginVaultRead\\("${name}"\\)`).test(bodyOf(starter)), bodyOf(starter))
  check(`${handler}() refuses an answer from a vault that has closed`,
    new RegExp(`if \\(vaultReadIsStale\\("${name}"\\)\\) return`).test(bodyOf(handler)), bodyOf(handler))
}

for (const fn of ["lockVault", "onUnlockSuccess", "onSessionHandoff", "onKeyringLookupFinished"]) {
  check(`${fn}() moves the vault generation on`,
    /vaultEpoch \+= 1/.test(bodyOf(fn)), bodyOf(fn))
}

console.log(`${pass} passed, ${failures.length} failed`)
if (failures.length) { console.error("\nFAILURES:\n  " + failures.join("\n  ")); process.exit(1) }
