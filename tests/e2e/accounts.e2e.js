#!/usr/bin/env node
// End to end: the real Service.qml in a headless Quickshell, driven over a
// test-only IPC target (config/shell.qml). Everything outside the plugin is a
// stand-in in bin/ -- `bw` (one account per data directory, like the real
// one), a file-backed `secret-tool`, a reversible `systemd-creds` -- except
// the committed unlock tool, `argon2`, `jq` and `node`, which run for real.
//
// Hermetic: a fresh temporary HOME, XDG dirs and runtime dir, and an
// environment built from scratch (nothing of the caller's is passed on), so
// it touches no real vault, keyring or shell. No network.
//
// Needs: quickshell (0.3+), argon2, jq, cmp (diffutils).
//
//   node tests/e2e/accounts.e2e.js

const { createSuite, privateScratchDir } = require("../harness")
const { createShell, sleep } = require("./shell")
const fs = require("fs")
const path = require("path")

const { check, done, failures } = createSuite("e2e-accounts")

const shell = createShell("e2e-accounts", check)
const { keyring, bwLog, env, q, product, state, expect } = shell
const accountsDir = path.join(env.XDG_DATA_HOME, "qs-bitwarden-cli", "accounts")
const startShell = shell.start
const stopShell = shell.stop

const addedDirs = () => fs.existsSync(accountsDir)
  ? fs.readdirSync(accountsDir).filter(n => /^[0-9a-f]{16}$/.test(n)) : []
const emails = s => s.accounts.map(a => a.email).join(",")

let failedToRun = null
try {
  startShell()

  // --- two accounts, each with its own PIN ---
  q("open")
  expect("starts signed out on the default slot", s => s.status === "unauthenticated" && s.slot === "default")
  expect("the committed unlock tool passes its check", s => s.quick === true)
  q("login", "a@x", "pw-a@x")
  expect("account A logs in", s => s.status === "unlocked" && s.items.join() === "Login of a@x")
  expect("and is recorded", s => emails(s) === "a@x" && s.email === "a@x")
  expect("its password is stored for quick unlock", s => s.envelope !== null)
  // The vault helper holds the session key and the items' secrets.
  expect("the vault helper is up", s => s.helper === "active")
  expect("and holds the session key, not the shell", s => s.sessionHeld === true)
  expect("the list here has no password, only that there is one",
    s => s.passwords.join() === "" && s.hasPasswords.join() === "true")
  q("copyFirst")
  expect("a copy reaches wl-copy from the helper", () => {
    try { return fs.readFileSync(bwLog + ".clipboard", "utf8") === "x" } catch (e) { return false }
  })
  q("setPin", "111111", "pw-a@x")
  expect("A gets a PIN", s => s.pinConfigured && s.pinReady)
  q("lock")
  expect("A locks", s => s.status === "locked")

  q("addAccount")
  expect("adding goes to a fresh slot's login", s => s.status === "unauthenticated" && s.slot !== "default" && s.adding)
  expect("where A's PIN is not offered", s => !s.pinReady)
  q("login", "b@x", "pw-b@x")
  expect("account B logs in beside A", s => s.status === "unlocked" && s.items.join() === "Login of b@x")
  expect("both are listed, B active", s => emails(s) === "a@x,b@x" && s.accounts[1].active && !s.adding)
  q("setPin", "222222", "pw-b@x")
  expect("B gets its own PIN", s => s.pinConfigured)

  q("switchTo", "a@x")
  expect("switching to A locks B and shows A locked", s => s.status === "locked" && s.slot === "default" && s.items.length === 0)
  expect("with A's PIN ready", s => s.pinReady && s.email === "a@x")
  q("pinUnlock", "111111")
  expect("A unlocks with its PIN", s => s.status === "unlocked" && s.items.join() === "Login of a@x")

  // From an unlocked account: the lock's scrub borrows the status processes.
  q("switchTo", "b@x")
  expect("switching from an unlocked account to B", s => s.status === "locked" && s.slot !== "default" && s.pinReady && s.email === "b@x")
  q("pinUnlock", "111111")
  expect("A's PIN does not open B", s => s.status === "locked" && /Incorrect PIN/.test(s.pinUnlockError))
  q("pinUnlock", "222222")
  expect("B's PIN does", s => s.status === "unlocked" && s.items.join() === "Login of b@x")

  const log = fs.readFileSync(bwLog, "utf8").split("\n")
  check("B signed in inside its own directory, never bw's",
    log.some(l => /\/accounts\/[0-9a-f]{16}\tlogin b@x /.test(l)) && !log.some(l => l.startsWith("<own>\tlogin b@x")),
    log.join("\n"))

  q("logout")
  expect("logging out of B moves to A, locked", s => !s.logoutPending && s.status === "locked" && s.slot === "default" && emails(s) === "a@x")
  expect("A still has its PIN", s => s.pinReady)
  q("pinUnlock", "111111")
  expect("and it still works", s => s.status === "unlocked" && s.items.join() === "Login of a@x")
  expect("B's keyring entries are gone and A's remain",
    () => fs.readdirSync(keyring).sort().join() === "session,unlock_envelope")
  expect("B's directory is gone", () => addedDirs().length === 0)

  // --- cancelling an add, a restart, the product IPC, a duplicate ---
  q("addAccount")
  expect("adding again", s => s.adding && s.status === "unauthenticated")
  q("cancelAdd")
  expect("cancel returns to A, locked", s => !s.adding && s.slot === "default" && s.status === "locked")
  expect("the abandoned slot leaves nothing", () => addedDirs().length === 0)
  q("unlock", "pw-a@x")
  expect("A unlocks with its password", s => s.status === "unlocked")
  q("addAccount")
  q("login", "b@x", "pw-b@x")
  expect("B signs in again", s => s.status === "unlocked" && s.accounts.length === 2 && !s.adding)
  expect("and its session is remembered", () => fs.readdirSync(keyring).some(n => /^session@[0-9a-f]{16}$/.test(n)))

  stopShell()
  startShell()
  q("open")
  expect("a restart comes back on B, unlocked from its remembered session",
    s => s.slot !== "default" && s.status === "unlocked" && s.items.join() === "Login of b@x")
  let listed = null
  try { listed = JSON.parse(product("accounts")) } catch (e) {}
  check("the IPC lists both accounts, and nothing secret",
    listed && listed.accounts.map(a => a.email).join() === "a@x,b@x" && listed.accounts[1].active
      && !/slot|userId|id-/.test(JSON.stringify(listed)), JSON.stringify(listed))
  check("the IPC switches by email, ignoring case", product("switchAccount", "A@X") === "switching", "")
  expect("to A, locked", s => s.slot === "default" && s.status === "locked")
  check("an unknown email is refused", product("switchAccount", "nobody@x") === "unknown", "")

  // Switch the moment A unlocks, while its remembered session is still being
  // written: the cleanup must reach A's entry, not B's.
  q("unlock", "pw-a@x")
  expect("A unlocks", s => s.status === "unlocked")
  q("switchTo", "b@x")
  expect("an immediate switch to B", s => s.status === "locked" && s.slot !== "default")
  sleep(2500)
  check("A's remembered session did not outlive the switch",
    !fs.readdirSync(keyring).includes("session"), fs.readdirSync(keyring).join())
  q("switchTo", "a@x")
  expect("back to A", s => s.slot === "default" && s.status === "locked")
  q("unlock", "pw-a@x")
  expect("A unlocks again", s => s.status === "unlocked")
  const oldB = state().accounts.find(a => a.email === "b@x").slot
  q("addAccount")
  q("login", "b@x", "pw-b@x")
  expect("signing B in a second time replaces its older sign-in",
    s => s.status === "unlocked" && s.accounts.length === 2 && !s.accounts.some(a => a.slot === oldB))
  expect("and deletes the older one's directory", () => !addedDirs().includes(oldB))
  check("and its keyring entries", !fs.readdirSync(keyring).some(n => n.endsWith("@" + oldB)), fs.readdirSync(keyring).join())

  q("logout")
  expect("logging out of B moves to A", s => s.slot === "default" && s.status === "locked" && s.accounts.length === 1)
  q("logout")
  expect("logging out of the last account leaves a clean login",
    s => s.status === "unauthenticated" && s.accounts.length === 0 && s.slot === "default")
  check("and an empty keyring", fs.readdirSync(keyring).length === 0, fs.readdirSync(keyring).join())

  const errors = shell.scriptErrors()
  check("the shell logged no script errors", errors.length === 0, errors.join("\n"))
} catch (e) {
  failedToRun = e
} finally {
  if (failedToRun || failures.length) console.error("--- shell log (tail) ---\n" + shell.logTail())
  shell.cleanup()
}

// --- Node's compile cache for bw: off unless the setting is on ---
// What matters is what reaches `bw`, so the stand-in logs the variable it was
// started with (bw.log.cache: "<variable or <unset>>\t<data dir>\t<args>").
// Both shells below are started with a NODE_COMPILE_CACHE of someone else's
// choosing, as a shell that inherited one would be.
const cacheLines = sh => {
  const file = sh.bwLog + ".cache"
  return fs.existsSync(file) ? fs.readFileSync(file, "utf8").split("\n").filter(Boolean).map(l => {
    const [cache, dir, args] = l.split("\t")
    return { cache, dir, args }
  }) : []
}
const seen = (sh, pattern) => cacheLines(sh).filter(l => pattern.test(l.args))
// A cache home the check has to accept: one this suite itself found to be
// the user's own up to / (harness.privateScratchDir(), plain filesystem
// calls). The check is not asked: if it refuses this, the scenario fails.
// Where the machine has no such directory, the default (under /tmp, which
// the check refuses) still shows the setting-off case.
const trustedRoot = privateScratchDir(".qsbw-e2e-cache-")
if (!failedToRun) {
  const inherited = path.join(fs.mkdtempSync("/tmp/qsbw-e2e-inherited-"), "cache")
  const cacheHome = trustedRoot ? path.join(trustedRoot, "off") : ""
  if (cacheHome) fs.mkdirSync(cacheHome, { mode: 0o700 })
  const second = createShell("e2e-accounts-cache-off", check,
    { env: Object.assign({ NODE_COMPILE_CACHE: inherited }, cacheHome ? { XDG_CACHE_HOME: cacheHome } : {}) })
  try {
    second.start()
    second.q("open")
    second.q("login", "a@x", "pw-a@x")
    second.expect("setting off, inherited cache variable: the account logs in and its list is read",
      s => s.status === "unlocked" && s.items.join() === "Login of a@x")
    second.q("lock")
    second.expect("it locks", s => s.status === "locked")
    second.q("unlock", "pw-a@x")
    second.expect("and unlocks", s => s.status === "unlocked" && s.items.join() === "Login of a@x")
    second.product("sync")
    second.expect("and syncs", () => seen(second, /^sync$/).length === 1)
    const lines = cacheLines(second)
    check("bw ran for the version probe, status, login, the list, lock, unlock and sync",
      [/^-v$/, /^status$/, /^login /, /^list items$/, /^lock$/, /^unlock /, /^sync$/].every(p => lines.some(l => p.test(l.args))),
      lines.map(l => l.args).join(" | "))
    check("and not one of them saw a NODE_COMPILE_CACHE", lines.length > 0 && lines.every(l => l.cache === "<unset>"),
      JSON.stringify(lines.filter(l => l.cache !== "<unset>")))
    check("the service never accepted a directory, nor checked one",
      second.state().compileCache === "" && second.state().compileCacheState === "off", JSON.stringify(second.state().compileCacheState))
    check("nothing was created in the cache home, though this one would have passed the check",
      !fs.existsSync(path.join(second.env.XDG_CACHE_HOME, "qs-bitwarden-cli")),
      fs.existsSync(second.env.XDG_CACHE_HOME) ? fs.readdirSync(second.env.XDG_CACHE_HOME).join() : "")
    check("and nothing at the inherited path", !fs.existsSync(inherited))
    const errors = second.scriptErrors()
    check("that shell logged no script errors", errors.length === 0, errors.join("\n"))
  } catch (e) {
    failedToRun = e
  } finally {
    if (failedToRun) console.error("--- shell log (tail) ---\n" + second.logTail())
    second.cleanup()
    fs.rmSync(path.dirname(inherited), { recursive: true, force: true })
  }
}
if (!failedToRun && !trustedRoot) {
  console.log("e2e-accounts: SKIPPED the compile cache's setting-on scenario: this user can write to no directory whose whole ancestor chain is its own or root's and closed to group and others ($XDG_RUNTIME_DIR, $RUNNER_TEMP, the account's home)")
}
if (!failedToRun && trustedRoot) {
  const inherited = path.join(trustedRoot, "inherited")
  const cacheHome = path.join(trustedRoot, "on")
  const wanted = path.join(cacheHome, "qs-bitwarden-cli", "node-compile-cache")
  const third = createShell("e2e-accounts-cache-on", check,
    { env: { NODE_COMPILE_CACHE: inherited, XDG_CACHE_HOME: cacheHome, QSBW_E2E_COMPILE_CACHE: "1" } })
  const since = n => cacheLines(third).slice(n)
  try {
    third.start()
    third.expect("setting on: a cache home of the user's own is accepted, as the path the check printed",
      s => s.compileCache === wanted && s.compileCacheState === "accepted")
    check("and made private", (fs.statSync(wanted).mode & 0o7777) === 0o700 && (fs.statSync(path.dirname(wanted)).mode & 0o7777) === 0o700)
    third.q("open")
    third.q("login", "a@x", "pw-a@x")
    third.expect("the account logs in", s => s.status === "unlocked" && s.items.join() === "Login of a@x")
    third.expect("the check made as the vault opened has answered", s => s.compileCacheState === "accepted" && s.compileCache === wanted)
    third.product("sync")
    third.expect("and syncs", () => seen(third, /^sync$/).length === 1)
    check("the login, which is given the password, ran without the cache though one was accepted",
      seen(third, /^login /).length >= 1 && seen(third, /^login /).every(l => l.cache === "<unset>"), JSON.stringify(seen(third, /^login /)))
    check("the list read the opening started ran without it too: its check had not answered yet",
      seen(third, /^list items$/).length >= 1 && seen(third, /^list items$/)[0].cache === "<unset>", JSON.stringify(seen(third, /^list items$/)))
    check("the sync after it saw exactly the accepted directory",
      seen(third, /^sync$/).every(l => l.cache === wanted), JSON.stringify(seen(third, /^sync$/)))
    check("no bw saw anything else: the accepted directory, or none",
      cacheLines(third).every(l => l.cache === wanted || l.cache === "<unset>") && !fs.existsSync(inherited),
      JSON.stringify(cacheLines(third).filter(l => l.cache !== wanted && l.cache !== "<unset>")))
    check("the version probe never gets it, setting on or not",
      seen(third, /^-v$/).length >= 1 && seen(third, /^-v$/).every(l => l.cache === "<unset>"), JSON.stringify(seen(third, /^-v$/)))

    // A second account, signed out again: its slot is retired by a `bw
    // logout` of its own, which never gets the cache.
    third.q("addAccount")
    third.expect("a second account can be added", s => s.adding && s.status === "unauthenticated")
    third.q("login", "b@x", "pw-b@x")
    third.expect("and signs in", s => s.status === "unlocked" && s.items.join() === "Login of b@x" && s.accounts.length === 2)
    const slotB = third.state().slot
    third.q("logout")
    third.expect("logging out of it returns to the first", s => s.slot === "default" && s.accounts.length === 1)
    third.expect("its slot is retired by a logout of its own",
      () => seen(third, /^logout$/).filter(l => l.dir.endsWith("/" + slotB)).length >= 2)
    const logouts = seen(third, /^logout$/).filter(l => l.dir.endsWith("/" + slotB))
    check("the retiring logout ran without the cache",
      logouts.some(l => l.cache === "<unset>") && logouts.every(l => l.cache === wanted || l.cache === "<unset>"),
      JSON.stringify(logouts))
    third.q("unlock", "pw-a@x")
    third.expect("the first account unlocks again", s => s.status === "unlocked" && s.compileCacheState === "accepted")
    check("no unlock and no login, of either account, was given the cache",
      seen(third, /^unlock /).length >= 1 && seen(third, /^unlock |^login /).every(l => l.cache === "<unset>"),
      JSON.stringify(seen(third, /^unlock |^login /)))

    // Off: the next bw has none, and the directory stays.
    let mark = cacheLines(third).length
    third.q("setCompileCache", "false")
    third.expect("turned off, no directory is on offer", s => s.compileCache === "" && s.compileCacheState === "off")
    third.product("sync")
    third.expect("the next bw runs", () => since(mark).some(l => l.args === "sync"))
    check("and sees no NODE_COMPILE_CACHE", since(mark).every(l => l.cache === "<unset>"), JSON.stringify(since(mark)))
    check("the directory is left where it was", fs.existsSync(wanted))

    // On again: checked again, then used.
    third.q("setCompileCache", "true")
    third.expect("turned on again, the directory is checked and accepted", s => s.compileCache === wanted)
    mark = cacheLines(third).length
    third.product("sync")
    third.expect("the next bw runs", () => since(mark).some(l => l.args === "sync"))
    check("and sees the accepted directory", since(mark).every(l => l.cache === wanted), JSON.stringify(since(mark)))

    // Something planted in the cache while the vault was locked: the check
    // made as the vault opens refuses it, and bw goes without.
    third.q("lock")
    third.expect("it locks", s => s.status === "locked")
    fs.symlinkSync("/etc/hostname", path.join(wanted, "planted"))
    mark = cacheLines(third).length
    third.q("unlock", "pw-a@x")
    third.expect("after a symlink was put in the cache, the opening's check refuses the directory",
      s => s.status === "unlocked" && s.compileCacheState === "refused" && s.compileCache === "" && s.items.join() === "Login of a@x")
    third.product("sync")
    third.expect("a bw runs after it", () => since(mark).some(l => l.args === "sync"))
    check("and none since the vault opened saw the cache: not the unlock, not the reads, not the sync",
      since(mark).filter(l => /^unlock |^list |^sync$/.test(l.args)).length >= 3
        && since(mark).filter(l => !/^status$|^lock$/.test(l.args)).every(l => l.cache === "<unset>"), JSON.stringify(since(mark)))
    fs.unlinkSync(path.join(wanted, "planted"))
    third.q("lock")
    third.expect("it locks again", s => s.status === "locked")
    third.q("unlock", "pw-a@x")
    third.expect("with the symlink gone the next opening's check accepts it again",
      s => s.status === "unlocked" && s.compileCache === wanted && s.items.join() === "Login of a@x")
    mark = cacheLines(third).length
    third.product("sync")
    third.expect("the next bw runs", () => since(mark).some(l => l.args === "sync"))
    check("and sees the directory", since(mark).every(l => l.cache === wanted), JSON.stringify(since(mark)))
    const errors = third.scriptErrors()
    check("that shell logged no script errors either", errors.length === 0, errors.join("\n"))
  } catch (e) {
    failedToRun = e
  } finally {
    if (failedToRun) console.error("--- shell log (tail) ---\n" + third.logTail())
    third.cleanup()
  }
}
if (trustedRoot) fs.rmSync(trustedRoot, { recursive: true, force: true })
if (failedToRun) {
  console.error("e2e-accounts: " + failedToRun.message)
  process.exit(1)
}
done()
