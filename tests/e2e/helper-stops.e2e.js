#!/usr/bin/env node
// End to end: the vault never moves into the shell because the vault helper
// is gone. A headless shell (shell.js) with the real helper.
//
// - Killed four times, the helper is left stopped: the vault stays locked,
//   nothing of it is held in the shell, and the banner's "check again" brings
//   the helper back and the vault unlocks.
// - With `--settle`: four kills each a little over a minute apart do not add
//   up (the restart count clears once the helper has settled). About 5
//   minutes.
// - A helper that cannot be used when the shell starts (here, missing) leaves
//   the vault locked and runs no `bw` in the shell, unless
//   allowVaultWithoutHelper is set, and then the panel falls back and says so.
//
// Uses the helper built at vault/target/debug when there is one, else the
// shipped one (as CI does), and what shell.js needs.
//
//   node tests/e2e/helper-stops.e2e.js [--settle]

const { createSuite, repoRoot } = require("../harness")
const { createShell, sleep } = require("./shell")
const fs = require("fs")
const path = require("path")

const { check, done, failures } = createSuite("e2e-helper-stops")
const settle = process.argv.includes("--settle")
const scratch = fs.mkdtempSync("/tmp/qsbw-helper-stops-e2e-")

function helperPid(parent) {
  for (const entry of fs.readdirSync("/proc")) {
    if (!/^\d+$/.test(entry)) continue
    try {
      const stat = fs.readFileSync(`/proc/${entry}/stat`, "utf8")
      const ppid = Number(stat.slice(stat.lastIndexOf(")") + 2).split(" ")[1])
      if (ppid === parent && /^qs-bitwarden-va/.test(fs.readFileSync(`/proc/${entry}/comm`, "utf8"))) return Number(entry)
    } catch (e) {}
  }
  return 0
}

// `bw` commands that touch the vault: the version probe (a plain process,
// before any account) is not one.
const bwCalls = shell => {
  try {
    return fs.readFileSync(shell.bwLog, "utf8").split("\n").map(l => l.split("\t")[1])
      .filter(c => c && c !== "-v" && c !== "--version")
  } catch (e) { return [] }
}

// The plugin with the helper built in vault/target/debug in place of the
// shipped one, which may predate the checkout; the checkout as it is when
// nothing is built.
function pluginWithBuiltHelper(into) {
  const built = "vault/target/debug/qs-bitwarden-vault"
  if (!fs.existsSync(path.join(repoRoot, built))) return repoRoot
  fs.cpSync(repoRoot, into, {
    recursive: true,
    filter: src => {
      const rel = path.relative(repoRoot, src)
      if (/^\.git(\/|$)/.test(rel) || rel === "bin/x86_64-linux/qs-bitwarden-vault") return false
      if (/(^|\/)target(\/|$)/.test(rel)) return ["vault/target", "vault/target/debug", built].includes(rel)
      return true
    }
  })
  return into
}

function withoutHelper(into) {
  fs.cpSync(repoRoot, into, {
    recursive: true,
    filter: src => {
      const rel = path.relative(repoRoot, src)
      return !/^\.git(\/|$)/.test(rel) && !/(^|\/)target(\/|$)/.test(rel)
        && rel !== "bin/x86_64-linux/qs-bitwarden-vault"
    }
  })
  return into
}

function guarded(label, shell, body) {
  let failed = null
  try {
    shell.start()
    body()
    check(`${label}: no script errors`, shell.scriptErrors().length === 0, shell.scriptErrors().join("\n"))
  } catch (e) {
    failed = e
    check(`${label}: ran to the end`, false, String(e && e.message))
  } finally {
    if (failed || failures.length) console.error(`--- ${label} shell log (tail) ---\n` + shell.logTail())
    shell.cleanup()
  }
}

// `gapMs`: how long the helper stays up before each kill.
function kills(label, plugin, gapMs) {
  const shell = createShell("e2e-helper-stops", check, { plugin })
  guarded(label, shell, () => {
    shell.q("open")
    shell.q("login", "a@x", "pw-a@x")
    shell.expect(`${label}: signed in, the helper holding the key`,
      s => s.status === "unlocked" && s.helper === "active" && s.sessionHeld)
    for (let i = 1; i <= 4; i++) {
      if (gapMs) sleep(gapMs)
      const pid = helperPid(shell.pid())
      check(`${label}: kill ${i}: the helper runs`, pid > 0, "")
      if (pid) process.kill(pid, "SIGKILL")
      if (i < 4 || gapMs) {
        shell.expect(`${label}: kill ${i}: locked, and the helper is back`,
          s => s.status === "locked" && s.helper === "active" && !s.sessionHeld)
      }
    }
    if (gapMs) {
      shell.q("unlock", "pw-a@x")
      shell.expect(`${label}: kills spread out never stop the helper, and it unlocks`,
        s => s.status === "unlocked" && s.helper === "active" && s.sessionHeld)
      return
    }
    shell.expect(`${label}: the fourth kill leaves it stopped, the vault locked, the banner up`,
      s => s.helper === "stopped" && s.status === "locked" && !s.sessionHeld && /keeps stopping/.test(s.helperWarning))
    sleep(2000)
    const after = shell.state()
    check(`${label}: it stays stopped, never the fallback`, after.helper === "stopped" && after.status === "locked",
      JSON.stringify(after && { helper: after.helper, status: after.status }))
    shell.q("retryHelper")
    shell.expect(`${label}: checking again brings the helper back`, s => s.helper === "active" && s.helperWarning === "")
    shell.q("unlock", "pw-a@x")
    shell.expect(`${label}: and the vault unlocks`, s => s.status === "unlocked" && s.sessionHeld)
  })
}

function missing(label, allow) {
  const plugin = withoutHelper(path.join(scratch, allow ? "plugin-allowed" : "plugin-refused"))
  const shell = createShell("e2e-helper-stops", check, { plugin, env: { QSBW_E2E_ALLOW_NO_HELPER: allow ? "1" : "0" } })
  guarded(label, shell, () => {
    shell.q("open")
    if (allow) {
      shell.expect(`${label}: falls back, and says crash protection is off`,
        s => s.helper === "fallback" && /Crash protection is off/.test(s.helperWarning))
      shell.q("login", "a@x", "pw-a@x")
      shell.expect(`${label}: signs in with the vault in the shell`, s => s.status === "unlocked" && !s.sessionHeld)
      return
    }
    shell.expect(`${label}: the helper is stopped and the banner says the vault stays locked`,
      s => s.helper === "stopped" && /stays locked/.test(s.helperWarning) && /allowVaultWithoutHelper/.test(s.helperWarning))
    shell.q("login", "a@x", "pw-a@x")
    sleep(3000)
    const s = shell.state()
    check(`${label}: a login does not unlock`, s.status !== "unlocked" && s.helper === "stopped", s.status)
    check(`${label}: no vault command ran in the shell`, bwCalls(shell).length === 0, bwCalls(shell).join(" | "))
    shell.q("retryHelper")
    shell.expect(`${label}: checking again finds it still missing and stays stopped`,
      s => s.helper === "stopped" && /stays locked/.test(s.helperWarning))
    check(`${label}: still nothing ran`, bwCalls(shell).length === 0, bwCalls(shell).join(" | "))
  })
}

try {
  const plugin = pluginWithBuiltHelper(path.join(scratch, "plugin"))
  kills("four quick kills", plugin, 0)
  if (settle) kills("four kills a minute apart", plugin, 61000)
  missing("missing helper", false)
  missing("missing helper, allowed", true)
} finally {
  fs.rmSync(scratch, { recursive: true, force: true })
}
done()
