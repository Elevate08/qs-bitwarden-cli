#!/usr/bin/env node
// The vault's lifecycle drives the companion's. These tests pin the design's
// state table and the ordering rules around a lock: deny first, cancel work,
// drop private material, keep only the public projection, and never let the
// panel's own lock wait on a companion that will not answer.
//
//   node tests/ssh-agent-lifecycle.test.js

const fs = require("fs")
const path = require("path")

const repoRoot = path.join(__dirname, "..")
const Model = {}
new Function("exports", fs.readFileSync(path.join(repoRoot, "BitwardenModel.js"), "utf8")
  .replace(/^\.pragma library\s*$/m, "") + `
  exports.sshAgentVaultState = sshAgentVaultState
  exports.sshAgentIdentityPolicy = sshAgentIdentityPolicy
  exports.sshAgentLifecycleTransition = sshAgentLifecycleTransition
  exports.sshAgentLockAckTimeoutMs = sshAgentLockAckTimeoutMs
  exports.sshAgentVaultLockedLine = sshAgentVaultLockedLine
  exports.sshAgentLoggedOutLine = sshAgentLoggedOutLine
  exports.sshAgentRevokeGrantsLine = sshAgentRevokeGrantsLine
`)(Model)

let pass = 0
const failures = []
const check = (label, ok, detail) => ok ? pass++ : failures.push(`${label}\n    ${detail}`)
const eq = (label, actual, expected) =>
  check(label, actual === expected, `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`)

const ctx = extra => Object.assign({
  enabled: true, helperReady: true, loggedIn: true,
  unlocked: true, loading: false, hasPublicCache: true
}, extra || {})

// -------------------------------------------------------------------------
// The state table from the design, as one function
// -------------------------------------------------------------------------

eq("the feature off is its own state", Model.sshAgentVaultState(ctx({ enabled: false })), "disabled")
eq("a stopped companion is disabled too", Model.sshAgentVaultState(ctx({ helperReady: false })), "disabled")
eq("no account is logged out", Model.sshAgentVaultState(ctx({ loggedIn: false })), "logged-out")
eq("a load in flight is loading", Model.sshAgentVaultState(ctx({ loading: true })), "loading")
eq("an unlocked vault with keys is unlocked", Model.sshAgentVaultState(ctx()), "unlocked")
eq("locked with a cache keeps the cache",
  Model.sshAgentVaultState(ctx({ unlocked: false })), "locked-cached")
eq("locked before any load is empty",
  Model.sshAgentVaultState(ctx({ unlocked: false, hasPublicCache: false })), "locked-empty")

// Logged out outranks everything below it: an account change must not leave a
// public projection behind just because one was loaded a moment ago.
eq("logged out outranks a stale cache",
  Model.sshAgentVaultState(ctx({ loggedIn: false, hasPublicCache: true })), "logged-out")
eq("disabled outranks logged out",
  Model.sshAgentVaultState(ctx({ enabled: false, loggedIn: false })), "disabled")

const policy = state => Model.sshAgentIdentityPolicy(state)

for (const [state, publicIds, privateKeys, signing] of [
  ["disabled", false, false, "denied"],
  ["logged-out", false, false, "denied"],
  ["locked-empty", false, false, "needs-unlock"],
  ["loading", true, false, "denied"],
  ["unlocked", true, true, "allowed"],
  ["locked-cached", true, false, "needs-unlock"]
]) {
  const p = policy(state)
  eq(`${state} offers public identities: ${publicIds}`, p.publicIdentities, publicIds)
  eq(`${state} holds private keys: ${privateKeys}`, p.privateKeys, privateKeys)
  eq(`${state} signing is ${signing}`, p.signing, signing)
}

// Private keys exist in exactly one state, and it is the only one that signs.
const allStates = ["disabled", "logged-out", "locked-empty", "loading", "unlocked", "locked-cached"]
eq("private keys live in exactly one state",
  allStates.filter(s => policy(s).privateKeys).length, 1)
eq("only that state signs without a further unlock",
  allStates.filter(s => policy(s).signing === "allowed").join(","), "unlocked")
check("no state holds private keys without allowing signing",
  allStates.every(s => !policy(s).privateKeys || policy(s).signing === "allowed"), "mismatch")

// -------------------------------------------------------------------------
// Lifecycle transitions
// -------------------------------------------------------------------------

const at = (event, extra) => Model.sshAgentLifecycleTransition(event, ctx(extra))

// A lock denies first and asks for an acknowledgment it will not wait on.
const lock = at("lock", { loadActive: true })
check("lock tells the companion to lock",
  lock.controlLines.indexOf(Model.sshAgentVaultLockedLine(ctx().epoch || 0)) >= 0
    || lock.controlLines.some(l => l.indexOf('"vault_locked"') >= 0),
  JSON.stringify(lock.controlLines))
eq("lock cancels an in-flight load", lock.cancelLoad, true)
eq("lock starts no new load", lock.startLoad, false)
eq("lock waits for an acknowledgment", lock.awaitLockAck, true)
eq("lock keeps the public projection", lock.clearPublic, false)
eq("lock does not stop the helper", lock.stopHelper, false)
eq("the acknowledgment wait is bounded at two seconds", Model.sshAgentLockAckTimeoutMs(), 2000)

// Screen lock and suspend are locks. They are listed separately so the table
// says so, rather than leaving it to a reader to infer from the panel.
for (const event of ["screen-lock", "suspend"]) {
  const t = at(event, { loadActive: true })
  eq(`${event} locks the companion`, t.awaitLockAck, true)
  eq(`${event} cancels an in-flight load`, t.cancelLoad, true)
  eq(`${event} keeps the public projection`, t.clearPublic, false)
  check(`${event} sends the same line a lock does`,
    JSON.stringify(t.controlLines) === JSON.stringify(lock.controlLines), JSON.stringify(t.controlLines))
}

// Logout and account change clear the public projection too.
for (const event of ["logout", "account-change"]) {
  const t = at(event, { loadActive: true })
  eq(`${event} clears the public projection`, t.clearPublic, true)
  eq(`${event} cancels an in-flight load`, t.cancelLoad, true)
  check(`${event} tells the companion the account is gone`,
    t.controlLines.some(l => l.indexOf('"vault_logged_out"') >= 0), JSON.stringify(t.controlLines))
  check(`${event} does not merely lock`,
    !t.controlLines.some(l => l.indexOf('"vault_locked"') >= 0), JSON.stringify(t.controlLines))
  eq(`${event} waits for no acknowledgment`, t.awaitLockAck, false)
}

// Unlock and sync both ride the panel's existing read.
for (const event of ["unlock", "sync"]) {
  const t = at(event)
  eq(`${event} starts a key load`, t.startLoad, true)
  eq(`${event} clears nothing`, t.clearPublic, false)
  eq(`${event} sends no lifecycle line`, t.controlLines.length, 0)
}

// Startup into a vault the keyring already unlocked. A freshly started
// companion is in "locked, no cache yet" while the panel is unlocked, so
// startup is not evidence that the vault is locked.
const startup = at("startup", { unlocked: true, hasPublicCache: false })
eq("starting beside a remembered session loads keys", startup.startLoad, true)
const startupLocked = at("startup", { unlocked: false, hasPublicCache: false })
eq("starting into a locked vault loads nothing", startupLocked.startLoad, false)

// Disabling stops the companion outright; its socket and FIFO go with it.
const disabled = at("disable", { loadActive: true })
eq("disabling stops the helper", disabled.stopHelper, true)
eq("disabling cancels an in-flight load", disabled.cancelLoad, true)
eq("disabling clears the public projection", disabled.clearPublic, true)

const shutdown = at("shutdown", { loadActive: true })
eq("panel shutdown stops the helper", shutdown.stopHelper, true)
eq("panel shutdown cancels an in-flight load", shutdown.cancelLoad, true)

// Nothing is asked of a companion that is not there to answer.
for (const event of ["lock", "logout", "unlock", "sync", "screen-lock", "suspend"]) {
  const t = Model.sshAgentLifecycleTransition(event, ctx({ enabled: false, helperReady: false }))
  eq(`${event} sends nothing while disabled`, t.controlLines.length, 0)
  eq(`${event} starts no load while disabled`, t.startLoad, false)
  eq(`${event} waits for nothing while disabled`, t.awaitLockAck, false)
}

// A helper that has not finished its handshake cannot be sent lifecycle lines,
// but a lock must still cancel local work rather than quietly doing nothing.
const lockNoHelper = Model.sshAgentLifecycleTransition("lock", ctx({ helperReady: false, loadActive: true }))
eq("a lock with no live helper still cancels local work", lockNoHelper.cancelLoad, true)
eq("a lock with no live helper waits for no acknowledgment", lockNoHelper.awaitLockAck, false)

// -------------------------------------------------------------------------
// The panel's own lock is never blocked by the companion
// -------------------------------------------------------------------------

// The panel is three QML files now -- the SSH settings sections and the
// approval screen have their own. A check that reads only the largest one
// silently narrows as markup moves out of it.
const panelSrc = ["Panel.qml", "SshAgentSettings.qml", "SshApprovalScreen.qml"]
  .map(file => fs.readFileSync(path.join(repoRoot, file), "utf8"))
  .join("\n")
const lockVault = panelSrc.slice(panelSrc.indexOf("function lockVault()"),
  panelSrc.indexOf("function lockVault()") + 1400)

check("locking runs bw lock without waiting on the companion",
  /lockProc\.running = true/.test(lockVault) && !/await|\.wait\(/.test(lockVault), lockVault.slice(0, 300))
check("locking reports the vault locked on the panel's own schedule",
  /status = "locked"/.test(lockVault), "lockVault never sets the locked status")
check("locking notifies the companion",
  /applySshAgentLifecycle\("lock"\)|sshAgentVaultLockedLine/.test(lockVault),
  "lockVault never tells the companion")

check("a lock acknowledgment timeout kills the helper",
  /id: sshAgentLockAckTimer[\s\S]{0,400}?onTriggered:[\s\S]{0,200}?(sshAgentProc\.running = false|killSshAgentHelper)/
    .test(panelSrc),
  "no acknowledgment timeout kills the helper")
check("the acknowledgment timer uses the model's bound",
  /id: sshAgentLockAckTimer[\s\S]{0,200}?interval: Model\.sshAgentLockAckTimeoutMs\(\)/.test(panelSrc),
  "the acknowledgment timeout is not the model's")
check("a locked acknowledgment stops the timer",
  /"locked"[\s\S]{0,300}?sshAgentLockAckTimer\.stop\(\)/.test(panelSrc),
  "the locked acknowledgment never stops the kill timer")

check("logout tells the companion the account is gone",
  /function logoutAccount\(\)[\s\S]{0,900}?applySshAgentLifecycle\("logout"\)/.test(panelSrc),
  "logoutAccount never notifies the companion")
check("screen lock and suspend reach the companion through the lock path",
  /function onScreenLockState[\s\S]{0,300}?lockVault\(\)/.test(panelSrc)
    && /function onSleepSignal[\s\S]{0,900}?lockVault\(\)/.test(panelSrc),
  "screen lock or suspend does not lock the vault")

check("the gate opening arms a startup load",
  /onSshAgentGateOpenChanged[\s\S]{0,1400}?sshAgentStartupLoadTimer\.restart\(\)/.test(panelSrc),
  "the gate opening never arms a startup load")
check("a remembered unlocked session loads keys once the helper is ready",
  /function maybeStartupLoad\(\)[\s\S]{0,1200}?applySshAgentLifecycle\("startup"\)/.test(panelSrc),
  "nothing applies the startup transition")
// On a shell restart the handshake and the first `bw status` race, so waiting
// on only one of them loses the load whenever the other is second.
check("both edges of the startup race trigger the load",
  /id: sshAgentStartupLoadTimer[\s\S]{0,200}?maybeStartupLoad\(\)/.test(panelSrc)
    && /onStatusChanged:[\s\S]{0,200}?maybeStartupLoad\(\)/.test(panelSrc),
  "only one edge triggers the startup load")
// The panel's first read is launched before the helper handshakes, so the
// completion of that read is the third edge that can owe a key load.
check("a completed read re-checks whether a startup load is owed",
  /function onListFinished\(rawJson\)[\s\S]{0,900}?maybeStartupLoad\(\)/.test(panelSrc),
  "a finished read never re-checks for an owed startup load")
check("a startup attempt is recorded before it runs, not after",
  /sshAgentLoadedForVaultEpoch = root\.vaultEpoch\s*\n\s*applySshAgentLifecycle\("startup"\)/.test(panelSrc),
  "a failed startup load could relaunch itself")
check("the startup load happens once per vault epoch, not once per edge",
  /function maybeStartupLoad\(\)[\s\S]{0,1200}?sshAgentLoadedForVaultEpoch === root\.vaultEpoch/.test(panelSrc),
  "nothing stops the startup load repeating")

// The lock acknowledgment is what stops the kill timer, so it has to be
// consumed wherever the companion's messages are handled.
const messageHandler = panelSrc.slice(
  panelSrc.indexOf("function onSshAgentMessage(message)"),
  panelSrc.indexOf("function syncSshAgentSupervision()"))
check("the companion's own events are consumed rather than ignored",
  /message\.type === "locked"/.test(messageHandler) && /message\.type === "keys_loaded"/.test(messageHandler),
  "onSshAgentMessage ignores the lock acknowledgment or the load result")

// Turning the feature off stops the helper through the supervisor, which is a
// different path from the lifecycle table -- so the table's clearPublic has to
// be applied explicitly or the projection is left on disk by a feature that is
// no longer running.
check("disabling the feature clears the public projection",
  /onSshAgentEnabledChanged[\s\S]{0,700}?applySshAgentLifecycle\("disable"\)/.test(panelSrc),
  "disabling never applies the disable transition")

// A restarted helper is empty even when the vault epoch has not moved: the
// keystore lives in the helper's memory, not the vault's. Keying the
// startup-load guard on the vault epoch alone leaves a fresh helper keyless
// until something unrelated happens to bump it.
check("a new helper is always eligible for a load",
  /onSshAgentGateOpenChanged[\s\S]{0,700}?sshAgentLoadedForVaultEpoch = -1/.test(panelSrc),
  "a restarted helper inherits the old load bookkeeping and never loads")
check("a departed helper's key count is not left standing",
  /onSshAgentGateOpenChanged[\s\S]{0,700}?sshAgentKeyCount = 0/.test(panelSrc),
  "the panel keeps reporting keys a dead helper no longer holds")

// -------------------------------------------------------------------------
// Control lines
// -------------------------------------------------------------------------

eq("revoke_grants is a versioned v1 line", Model.sshAgentRevokeGrantsLine(),
  JSON.stringify({ v: 1, type: "revoke_grants" }) + "\n")

for (const line of [Model.sshAgentVaultLockedLine(3), Model.sshAgentLoggedOutLine(),
                    Model.sshAgentRevokeGrantsLine()]) {
  check("no lifecycle line carries key material or a session token",
    line.indexOf("BW_SESSION") < 0 && line.indexOf("privateKey") < 0 && line.indexOf("PRIVATE") < 0, line)
}

if (failures.length) {
  console.error(`\n${failures.length} failed, ${pass} passed\n`)
  failures.forEach(f => console.error(`  FAIL ${f}`))
  process.exit(1)
}
console.log(`ssh-agent-lifecycle: ${pass} passed`)
