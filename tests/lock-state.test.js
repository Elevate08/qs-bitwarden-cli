#!/usr/bin/env node
// What must stop when the vault is not open:
//
// 1. The auto-lock also runs on the wall clock (Qt Timers pause in suspend).
// 2. Minute counts from shell.json are validated (NaN reads as 0 = never, and
//    oversized values overflow Timer.interval).
// 3. A `bw` read that finishes after a lock is discarded.
//
//   node tests/lock-state.test.js

const { createSuite, functionBody, loadModule, read, readPluginSource } = require("./harness")

const Model = loadModule()

const { check, done } = createSuite("lock-state")

const panelSrc = readPluginSource("Panel.qml")
const bodyOf = name => functionBody(panelSrc, name)

// --- 1. The schema is the same on both sides of shell.json ------------------
// The settings screen clamps to SETTINGS_SCHEMA and the marketplace shows
// manifest.json's min/max: they must agree.
const manifest = JSON.parse(read("manifest.json"))
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
// Every one of these can reach shell.json (`omarchy bar set`, hand edits).
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
  // The floor means "off", so below it is a bad value (default), not zero.
  ["autoLockMinutes", -5,        15,   "a negative count is the default, NOT 0/never"],
  ["autoLockMinutes", "-1",      15,   "including the string form"],
  ["autoLockMinutes", -Infinity, 15,   "and the one that arrives as -Infinity"],
  ["autoLockMinutes", 15.9,      15,   "a fraction truncates rather than reaching the Timer"],
  ["clearClipboardSec", 100000,  300,  "the clipboard timeout has its own ceiling"],
  ["clearClipboardSec", "soon",  30,   "and its own default"],
  ["clearClipboardSec", -1,      30,   "and a negative there is not 'never clear' either"],
  ["autoCopyTotpSec", 999,       30,   "so does the TOTP delay"],
  ["autoCopyTotpSec", "off",     3,    "and its default is not 0 either"],
  ["autoCopyTotpSec", -3,        3,    "and a negative is its default too"],
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
  ["totp",          "startTotpFetch",     "onTotpFinished"],
  ["sends",         "loadSends",          "onSendsLoaded"],
]) {
  check(`${starter}() records the vault generation`,
    new RegExp(`beginVaultRead\\("${name}"\\)`).test(bodyOf(starter)), bodyOf(starter))
  check(`${handler}() refuses an answer from a vault that has closed`,
    new RegExp(`if \\(vaultReadIsStale\\("${name}"\\)\\) return`).test(bodyOf(handler)), bodyOf(handler))
}

// Writers and generated values can outlive a lock too. Their server-side
// effect may already have happened, but no completion may repopulate the
// locked panel, copy a newly created Send URL, or navigate back to main.
for (const [name, starter, handler] of [
  ["sendCreate",  "submitCreateSend",   "onSendCreated"],
  ["sendDelete",  "deleteSend",         "onSendDeleted"],
  ["generator",   "regenerate",         "onGenerated"],
  ["folderCreate", "submitNewFolder",    "onFolderCreated"],
  ["sync",        "syncVault",          "onSyncFinished"],
  ["itemSave",    "saveItemForm",       "onSaveItemFinished"],
  ["itemDelete",  "deleteCurrentItem",  "onDeleteItemFinished"],
  ["attachment",  "pumpAttachmentQueue", "onAttachmentDownloaded"],
]) {
  check(`${starter}() stamps the vault operation`,
    new RegExp(`beginVaultRead\\("${name}"\\)`).test(bodyOf(starter)), bodyOf(starter))
  check(`${handler}() drops a completion from a vault that has closed`,
    new RegExp(`if \\(vaultReadIsStale\\("${name}"\\)\\)[\\s\\S]{0,140}return`).test(bodyOf(handler)), bodyOf(handler))
}

const droppedState = bodyOf("dropVaultState") + bodyOf("resetItemForm")
check("the local vault purge resets the item form",
  /resetItemForm\(\)/.test(bodyOf("dropVaultState")), bodyOf("dropVaultState"))
check("a queued TOTP request is pinned to the vault generation that queued it",
  /totpQueuedEpoch\s*=\s*vaultEpoch/.test(bodyOf("fetchTotp"))
    && /queuedEpoch\s*===\s*root\.vaultEpoch/.test(bodyOf("continueTotpQueue")),
  bodyOf("fetchTotp") + "\n" + bodyOf("continueTotpQueue"))
check("every status request records the current vault generation",
  /beginEpochOperation\("status"\)/.test(bodyOf("runStatusCheck")), bodyOf("runStatusCheck"))
check("status completion refuses a result from an earlier vault generation",
  /if \(epochOperationIsStale\("status"\)\) \{\s*restartStaleStatusProbe\(\)\s*return\s*\}/.test(bodyOf("onStatusFinished")),
  bodyOf("onStatusFinished"))
check("status requests use the generation-stamped launcher",
  (panelSrc.match(/statusProc\.running\s*=\s*true/g) || []).length === 1
    && /statusProc\.running\s*=\s*true/.test(bodyOf("runStatusCheck")),
  `direct starts: ${(panelSrc.match(/statusProc\.running\s*=\s*true/g) || []).length}`)
check("session handoff reads record and verify their vault generation",
  /beginEpochOperation\("sessionHandoff"\)/.test(bodyOf("refreshStatus"))
    && /if \(epochOperationIsStale\("sessionHandoff"\)\) \{\s*restartStaleStatusProbe\(\)\s*return\s*\}/.test(bodyOf("onSessionHandoff")),
  bodyOf("refreshStatus") + "\n" + bodyOf("onSessionHandoff"))
check("remembered-session lookups record and verify their vault generation",
  /beginEpochOperation\("keyringLookup"\)/.test(bodyOf("onSessionHandoff"))
    && /if \(epochOperationIsStale\("keyringLookup"\)\) \{\s*restartStaleStatusProbe\(\)\s*return\s*\}/.test(bodyOf("onKeyringLookupFinished")),
  bodyOf("onSessionHandoff") + "\n" + bodyOf("onKeyringLookupFinished"))
check("logout closes any terminal handoff acceptance window",
  /terminalLoginStartedAt\s*=\s*0/.test(bodyOf("logoutAccount")), bodyOf("logoutAccount"))
const abandonedAuth = bodyOf("abandonAuthSecrets") + bodyOf("clearLoginAttempt")
check("abandoning authentication clears every typed or staged auth secret",
  ["masterPassword", "loginPassword", "loginClientId", "loginClientSecret", "login2faCode",
    "pendingUnlockPassword", "authPasswordWriteValue", "pinEntry"].every(prop =>
      new RegExp(`\\b${prop}\\s*=\\s*""`).test(abandonedAuth)),
  abandonedAuth)
check("handoff, external unlock, and panel hide purge abandoned auth secrets",
  /cancelAuthPrewarm\(\)[\s\S]{0,100}abandonAuthSecrets\(\)/.test(bodyOf("onSessionHandoff"))
    && /if\s*\(st\.unlocked\)[\s\S]{0,400}abandonAuthSecrets\(\)/.test(bodyOf("onStatusFinished"))
    && /onOpenedChanged:[\s\S]{0,180}else[\s\S]{0,500}abandonAuthSecrets\(\)/.test(panelSrc),
  bodyOf("onSessionHandoff") + "\n" + bodyOf("onStatusFinished"))
check("an unlock from elsewhere takes down a waiting reader or key",
  /if\s*\(st\.unlocked\)[\s\S]{0,400}cancelFingerprintUnlock\(\)[\s\S]{0,120}cancelFidoUnlock\(\)/.test(bodyOf("onStatusFinished")),
  "a gate armed for a vault someone else unlocked leaves a device waiting on a touch")
check("closing the panel invalidates PIN and fingerprint unlock completions",
  /abandonAuthSecrets\(\)/.test(bodyOf("close"))
    && /pinUnlockSubmitted\s*=\s*false/.test(abandonedAuth)
    && /cancelFingerprintUnlock\(\)/.test(bodyOf("close")), bodyOf("close"))
check("closing the panel cancels authentication-method setup writes",
  /abandonPinSetup\(\)/.test(bodyOf("close"))
    && /abandonFingerprintSetup\(\)/.test(bodyOf("close")), bodyOf("close"))
check("leaving either authentication setup form cancels its in-flight write",
  /currentScreen\s*!==\s*"pin"[\s\S]*abandonPinSetup\(\)/.test(panelSrc)
    && /currentScreen\s*!==\s*"fingerprint"[\s\S]*abandonFingerprintSetup\(\)/.test(panelSrc)
    && /invalidateEpochOperation\("pinAdd"\)/.test(bodyOf("abandonPinSetup"))
    && /invalidateEpochOperation\("fingerprintAdd"\)/.test(bodyOf("abandonFingerprintSetup")),
  bodyOf("abandonPinSetup") + "\n" + bodyOf("abandonFingerprintSetup"))
check("PIN completion requires a still-active submitted unlock",
  /pinUnlockSubmitted\s*&&\s*sshAuthSurfaceActive\s*&&\s*status\s*===\s*"locked"/.test(bodyOf("onPinUnlockResult")),
  bodyOf("onPinUnlockResult"))
check("fingerprint password retrieval requires a live verified attempt",
  /fingerprintAuthorized/.test(bodyOf("onFingerprintPasswordRetrieved"))
    && /sshAuthSurfaceActive/.test(bodyOf("onFingerprintPasswordRetrieved"))
    && /status\s*!==\s*"locked"/.test(bodyOf("onFingerprintPasswordRetrieved")),
  bodyOf("onFingerprintPasswordRetrieved"))
check("remembered-session stores are generation-stamped and stale stores are cleared",
  /beginEpochOperation\("sessionStore"\)/.test(bodyOf("storeCurrentSession"))
    && /epochOperationIsStale\("sessionStore"\)/.test(bodyOf("onSessionStored"))
    // The account it was written for, which a switch may have left.
    && /requestSessionCredentialClear\(sessionStoreSlot\)/.test(bodyOf("onSessionStored"))
    && /sessionStoreSlot = activeSlot/.test(bodyOf("storeCurrentSession")),
  bodyOf("storeCurrentSession") + "\n" + bodyOf("onSessionStored"))
check("a newer session waits for an old store and its cleanup before being remembered",
  /keyringStoreProc\.running\s*\|\|\s*keyringClearProc\.running/.test(bodyOf("storeCurrentSession"))
    && /sessionStorePending\s*=\s*true/.test(bodyOf("storeCurrentSession"))
    && /sessionStorePending\s*=\s*rememberSession\s*&&\s*status\s*===\s*"unlocked"\s*&&\s*!!session/.test(bodyOf("onSessionStored"))
    // Asked again by a timer, not the clear's exit handler: a Process can
    // still read as running inside its own exit handler.
    && /if \(sessionStorePending\) storeCurrentSession\(\)/.test(bodyOf("pumpSessionKeyring"))
    && /id: busyRetryTimer[\s\S]{0,400}root\.sessionStorePending[\s\S]{0,200}root\.pumpSessionKeyring\(\)/.test(panelSrc),
  bodyOf("storeCurrentSession") + "\n" + bodyOf("onSessionStored"))
// A PIN is now a wrap in the envelope, and the invariant carries over: a wrap
// written for a vault generation that has ended, or a form that was left, is
// taken back out when it lands.
check("a PIN wrap cannot outlive the lock or abandonment it raced",
  /beginEpochOperation\("pinAdd"\)/.test(bodyOf("submitPinSetup"))
    && /epochOperationIsStale\("pinAdd"\)[\s\S]{0,300}?removeQuickUnlockMethod\(\{ kind: "remove", method: "pin" \}\)/
      .test(bodyOf("submitPinSetup")),
  bodyOf("submitPinSetup"))
// A fingerprint wrap written for a vault generation that ended (or an
// abandoned setup) is removed again.
check("a fingerprint wrap cannot outlive the lock or abandonment it raced",
  /beginEpochOperation\("fingerprintAdd"\)/.test(bodyOf("submitFingerprintSetup"))
    && /epochOperationIsStale\("fingerprintAdd"\)[\s\S]{0,300}?removeQuickUnlockMethod\(\{ kind: "remove", method: "fingerprint" \}\)/
      .test(bodyOf("submitFingerprintSetup")),
  bodyOf("submitFingerprintSetup"))
// And logout: the queue is emptied, and the final clear waits for a write
// already running rather than racing it.
check("logout drops queued envelope work and waits for a running write",
  /dropEnvelopeState\(\)/.test(bodyOf("forgetStoredCredentials"))
    && /envelopeJobs = \[\]/.test(bodyOf("dropEnvelopeState"))
    && /envelopeProc\.running/.test(bodyOf("credentialStoresRunning")),
  bodyOf("credentialStoresRunning"))
check("an envelope job that finishes after logout starts no follow-up",
  /job\.onDone && !logoutPending/.test(bodyOf("onEnvelopeJobExited")),
  bodyOf("onEnvelopeJobExited"))
check("a learned-association read cannot repopulate account metadata after logout",
  /associationsReadEpoch\s*=\s*associationsEpoch/.test(bodyOf("loadAssociations"))
    && /associationsReadEpoch\s*!==\s*associationsEpoch/.test(bodyOf("onAssociationsLoaded"))
    && /associationsEpoch\s*\+=\s*1/.test(bodyOf("forgetStoredCredentials")),
  bodyOf("loadAssociations") + "\n" + bodyOf("onAssociationsLoaded")
    + "\n" + bodyOf("forgetStoredCredentials"))
check("credential clears requested during another clear are repeated afterward",
  /sessionClearPending\s*=\s*true/.test(bodyOf("requestSessionCredentialClear"))
    && /pinClearPending\s*=\s*true/.test(bodyOf("requestPinCredentialClear"))
    && /masterClearPending\s*=\s*true/.test(bodyOf("requestMasterCredentialClear"))
    && /allCredentialsClearPending\s*=\s*true/.test(bodyOf("requestAllCredentialClear")),
  "one or more keyring clear paths cannot queue a repeat")
check("locking uses the centralized local vault purge",
  /dropVaultState\(\)/.test(bodyOf("lockVault")), bodyOf("lockVault"))
check("unreadable, locked, and logged-out status results purge local vault state",
  (bodyOf("onStatusFinished").match(/dropVaultState\(\)/g) || []).length >= 3,
  bodyOf("onStatusFinished"))
for (const [prop, empty] of [
  ["session", '""'], ["items", "[]"], ["filteredItems", "[]"],
  ["organizations", "[]"], ["folders", "[]"], ["detailItem", "null"],
  ["formCollections", "[]"], ["formCollectionIds", "[]"],
  ["formUsername", '""'], ["formUri", '""'],
  ["formNotes", '""'],
]) {
  check(`the local vault purge clears ${prop}`,
    droppedState.includes(`${prop} = ${empty}`),
    droppedState)
}
check("the local vault purge cancels and clears attachment work",
  /cancelAttachmentDownloads\(\)/.test(droppedState)
    && /attachmentQueue\s*=\s*\[\]/.test(bodyOf("cancelAttachmentDownloads"))
    && /attachmentBusyId\s*=\s*""/.test(bodyOf("cancelAttachmentDownloads")),
  droppedState + "\n" + bodyOf("cancelAttachmentDownloads"))
check("the local vault purge clears secret fields and collector buffers",
  /dropVaultSecrets\(\)/.test(droppedState), droppedState)

for (const fn of ["onUnlockSuccess", "onSessionHandoff", "onKeyringLookupFinished"]) {
  check(`${fn}() moves the vault generation on`,
    /vaultEpoch \+= 1/.test(bodyOf(fn)), bodyOf(fn))
}

done()
