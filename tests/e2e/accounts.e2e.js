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

const { createSuite } = require("../harness")
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
if (failedToRun) {
  console.error("e2e-accounts: " + failedToRun.message)
  process.exit(1)
}
done()
