#!/usr/bin/env node
// The vault's lifecycle drives the companion's: on lock, deny first, cancel
// work, drop private keys, keep the public projection, and never wait on the
// companion.
//
//   node tests/ssh-agent-lifecycle.test.js

const { createSuite, loadModule, readPluginSource } = require("./harness")
const path = require("path")

const Model = loadModule()

const { check, eq, done } = createSuite("ssh-agent-lifecycle")

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
  .map(readPluginSource)
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
check("a failed load is not treated as a lock acknowledgment",
  /message\.type === "load_failed"/.test(messageHandler)
    && !/"load_failed"[\s\S]{0,200}sshAgentLockAckTimer\.stop/.test(messageHandler),
  "load_failed must not stop the lock-ack timer; that timer is for vault_locked")
check("a failed load clears the startup-load guard so an unlocked vault can retry",
  /load_failed[\s\S]{0,500}sshAgentLoadedForVaultEpoch = -1/.test(messageHandler)
    && /load_failed[\s\S]{0,700}maybeStartupLoad\(\)/.test(messageHandler),
  "without clearing the epoch, maybeStartupLoad refuses a second attempt")
check("a load_failed for an older load is ignored",
  /message\.type === "load_failed"[\s\S]{0,400}?message\.epoch !== root\.sshAgentEpoch\) return[\s\S]{0,200}?sshAgentLoadFailStreak \+= 1/.test(messageHandler),
  "a stale failure clears the epoch a newer load already marked")
const startupLoad = panelSrc.slice(panelSrc.indexOf("function maybeStartupLoad()"),
  panelSrc.indexOf("onStatusChanged:", panelSrc.indexOf("function maybeStartupLoad()")))
check("a startup load waits for a nonce instead of spending the attempt without one",
  /isValidLoadId\(sshAgentNextLoadId\)[\s\S]{0,120}?return/.test(startupLoad)
    && startupLoad.indexOf("isValidLoadId") < startupLoad.indexOf("sshAgentLoadedForVaultEpoch = root.vaultEpoch"),
  startupLoad)
check("a nonce arriving picks up a load that was waiting for it",
  /function onSshAgentLoadIdRead\(raw\)[\s\S]{0,300}?maybeStartupLoad\(\)/.test(panelSrc),
  "nothing resumes the load once the nonce is ready")
check("an answered identity listing takes its prompt down",
  /request_cancelled[\s\S]{0,900}?reason === "released"[\s\S]{0,600}?list-identities[\s\S]{0,300}?if \(!listingAnswered\) return/.test(messageHandler),
  "a released listing is answered, not re-raised as an approval, so the prompt must close")
check("a failed load retries once, not in a loop",
  /property int sshAgentLoadFailStreak/.test(panelSrc)
    && /sshAgentLoadFailStreak \+= 1/.test(messageHandler)
    && /sshAgentLoadFailStreak === 1/.test(messageHandler),
  "a persistently bad FIFO must not relaunch the item list forever")
check("a successful load or a new helper clears the fail streak",
  /keys_loaded[\s\S]{0,600}sshAgentLoadFailStreak = 0/.test(messageHandler)
    && /onSshAgentGateOpenChanged[\s\S]{0,900}sshAgentLoadFailStreak = 0/.test(panelSrc)
    && /function dropVaultState\(\)[\s\S]{0,1200}sshAgentLoadFailStreak = 0/.test(panelSrc),
  "a later sync after recovery would inherit a spent retry")

// Disabling stops the helper via the supervisor, outside the lifecycle table,
// so the projection must be cleared explicitly.
check("disabling the feature clears the public projection",
  /onSshAgentEnabledChanged[\s\S]{0,700}?applySshAgentLifecycle\("disable"\)/.test(panelSrc),
  "disabling never applies the disable transition")

// A restarted helper is empty even if the vault epoch did not move.
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

// --- a killed helper's runtime files -----------------------------------------
//
// A helper killed with the shell objects (plugin disabled or removed) cannot
// remove its socket, FIFO and lock. The vault removes them from a detached
// script once the lock is free, and only then.
{
  const fs = require("fs")
  const os = require("os")
  const { spawnSync } = require("child_process")
  const names = ["ssh-agent.sock", "ssh-keys.fifo", "ssh-agent.lock"]
  const setup = () => {
    const rt = fs.mkdtempSync(path.join(os.tmpdir(), "qsbw-cleanup-"))
    const dir = path.join(rt, "qs-bitwarden-cli")
    fs.mkdirSync(dir, { mode: 0o700 })
    for (const n of names) fs.writeFileSync(path.join(dir, n), "")
    return { rt, dir }
  }
  const cmd = rt => Model.sshAgentRuntimeCleanupCommand(rt)

  const held = setup()
  const c = cmd(held.rt)
  const started = Date.now()
  const run = spawnSync("bash", ["-c", 'flock "$1" sleep 0.5 & sleep 0.1; shift; "$@"',
    "_", path.join(held.dir, "ssh-agent.lock"), ...c], { encoding: "utf8" })
  const waited = Date.now() - started
  check("cleanup waits for a held lock, then removes the files",
    run.status === 0 && !fs.existsSync(held.dir) && waited >= 400, `exit ${run.status}, waited ${waited} ms`)
  fs.rmSync(held.rt, { recursive: true, force: true })

  const linked = setup()
  const real = path.join(linked.rt, "real")
  fs.renameSync(linked.dir, real)
  fs.symlinkSync(real, linked.dir)
  spawnSync(cmd(linked.rt)[0], cmd(linked.rt).slice(1))
  check("cleanup never follows a symlinked runtime directory",
    names.every(n => fs.existsSync(path.join(real, n))), fs.readdirSync(real).join(","))
  fs.rmSync(linked.rt, { recursive: true, force: true })

  check("cleanup needs an absolute runtime directory", Model.sshAgentRuntimeCleanupCommand("relative") === null, "")

  const vaultSrc = readPluginSource("Service.qml")
  check("the vault runs the cleanup detached when it is destroyed with a helper",
    /Component\.onDestruction:[\s\S]{0,200}sshAgentRuntimeCleanupCommand\(root\.sshAgentRuntimeDir\)[\s\S]{0,80}Quickshell\.execDetached\(cleanup\)/.test(vaultSrc),
    "no cleanup on destruction")
}

done()
