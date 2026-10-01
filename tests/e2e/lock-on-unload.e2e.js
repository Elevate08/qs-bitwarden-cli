#!/usr/bin/env node
// End to end: with the session not remembered, unloading the shell while the
// vault is unlocked runs `bw lock` and leaves no valid session in bw's data.
// With the session remembered, the shell leaves it alone.
//
// The lock is checked where the shell holds the session itself (no vault
// helper), the path that starts it detached from the shell. Where the helper
// holds the key, the shell hands it the lock as it unloads, and Quickshell
// ends the helper before that write is sent; that case is not asserted here.
//
// Needs what shell.js needs.
//
//   node tests/e2e/lock-on-unload.e2e.js

const { createSuite, repoRoot } = require("../harness")
const { createShell, sleep } = require("./shell")
const fs = require("fs")
const path = require("path")

const { check, done } = createSuite("e2e-lock-on-unload")

const bwCalls = shell => {
  try { return fs.readFileSync(shell.bwLog, "utf8").split("\n").map(l => l.split("\t")[1]).filter(Boolean) } catch (e) { return [] }
}

// A copy of the plugin without the vault helper: the panel falls back to
// holding the session itself.
function pluginWithoutVaultHelper() {
  const dir = fs.mkdtempSync(path.join("/tmp", "qsbw-plugin-"))
  fs.cpSync(repoRoot, dir, {
    recursive: true,
    filter: src => {
      const rel = path.relative(repoRoot, src)
      return rel !== ".git" && !/^(vault|agent|unlock-key)\/target/.test(rel) && !/qs-bitwarden-vault$/.test(rel)
    }
  })
  return dir
}

function scenario(remember) {
  const label = remember ? "session remembered" : "session not remembered"
  const plugin = remember ? undefined : pluginWithoutVaultHelper()
  const shell = createShell("e2e-lock-on-unload", check,
    { plugin, env: { QSBW_E2E_REMEMBER_SESSION: remember ? "1" : "0" } })
  const sessionFile = path.join(shell.home, ".config", "Bitwarden CLI", "fake-session")
  try {
    shell.start()
    shell.q("open")
    shell.expect(label + ": starts signed out", s => s.status === "unauthenticated")
    shell.q("login", "a@x", "pw-a@x")
    shell.expect(label + ": unlocks", s => s.status === "unlocked"
      && (remember ? s.helper === "active" && s.sessionHeld === true : s.helper === "fallback" && s.sessionHeld === false))
    check(label + ": bw's session exists while unlocked", fs.existsSync(sessionFile), "")
    const before = bwCalls(shell).filter(c => c === "lock").length
    shell.quit()
    // The lock runs detached from the shell, so give it a moment.
    for (let i = 0; i < 50 && remember === false && fs.existsSync(sessionFile); i++) sleep(100)
    if (remember) sleep(1500)
    const locks = bwCalls(shell).filter(c => c === "lock").length - before
    if (remember) {
      check(label + ": no `bw lock` on unload", locks === 0, `${locks} lock call(s)`)
      check(label + ": bw's session is kept", fs.existsSync(sessionFile), "")
    } else {
      check(label + ": `bw lock` ran on unload", locks === 1, `${locks} lock call(s); calls: ${bwCalls(shell).join(" | ")}`)
      check(label + ": bw's session is gone", !fs.existsSync(sessionFile), "")
    }
    check(label + ": no script errors", shell.scriptErrors().length === 0, shell.scriptErrors().join("\n"))
  } catch (e) {
    check(label + ": ran", false, String(e && e.message) + "\n" + shell.logTail())
  } finally {
    shell.cleanup()
    if (plugin) fs.rmSync(plugin, { recursive: true, force: true })
  }
}

scenario(false)
scenario(true)
done()
